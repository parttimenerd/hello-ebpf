/** Auto-generated */
package me.bechberger.ebpf.runtime;

import me.bechberger.ebpf.annotations.EnumMember;
import me.bechberger.ebpf.annotations.InlineUnion;
import me.bechberger.ebpf.annotations.Offset;
import me.bechberger.ebpf.annotations.OriginalName;
import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.TrustedPtr;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.type.Enum;
import me.bechberger.ebpf.type.Ptr;
import me.bechberger.ebpf.type.Struct;
import me.bechberger.ebpf.type.TypedEnum;
import me.bechberger.ebpf.type.TypedefBase;
import me.bechberger.ebpf.type.Union;
import org.jetbrains.annotations.Nullable;
import static me.bechberger.ebpf.runtime.AaDefinitions.*;
import static me.bechberger.ebpf.runtime.AafsDefinitions.*;
import static me.bechberger.ebpf.runtime.Aat2870Definitions.*;
import static me.bechberger.ebpf.runtime.AccountDefinitions.*;
import static me.bechberger.ebpf.runtime.AcctDefinitions.*;
import static me.bechberger.ebpf.runtime.AcompDefinitions.*;
import static me.bechberger.ebpf.runtime.AcpiDefinitions.*;
import static me.bechberger.ebpf.runtime.AcpiphpDefinitions.*;
import static me.bechberger.ebpf.runtime.ActionDefinitions.*;
import static me.bechberger.ebpf.runtime.ActiveDefinitions.*;
import static me.bechberger.ebpf.runtime.AddDefinitions.*;
import static me.bechberger.ebpf.runtime.AddrDefinitions.*;
import static me.bechberger.ebpf.runtime.AddrconfDefinitions.*;
import static me.bechberger.ebpf.runtime.AdjustDefinitions.*;
import static me.bechberger.ebpf.runtime.AdlDefinitions.*;
import static me.bechberger.ebpf.runtime.Adp5520Definitions.*;
import static me.bechberger.ebpf.runtime.AdvisorDefinitions.*;
import static me.bechberger.ebpf.runtime.AeadDefinitions.*;
import static me.bechberger.ebpf.runtime.AerDefinitions.*;
import static me.bechberger.ebpf.runtime.AgpDefinitions.*;
import static me.bechberger.ebpf.runtime.AhashDefinitions.*;
import static me.bechberger.ebpf.runtime.AioDefinitions.*;
import static me.bechberger.ebpf.runtime.AlarmDefinitions.*;
import static me.bechberger.ebpf.runtime.AllocDefinitions.*;
import static me.bechberger.ebpf.runtime.AllocateDefinitions.*;
import static me.bechberger.ebpf.runtime.AmdDefinitions.*;
import static me.bechberger.ebpf.runtime.AmlDefinitions.*;
import static me.bechberger.ebpf.runtime.AnonDefinitions.*;
import static me.bechberger.ebpf.runtime.ApeiDefinitions.*;
import static me.bechberger.ebpf.runtime.ApicDefinitions.*;
import static me.bechberger.ebpf.runtime.ApparmorDefinitions.*;
import static me.bechberger.ebpf.runtime.AppendDefinitions.*;
import static me.bechberger.ebpf.runtime.ApplyDefinitions.*;
import static me.bechberger.ebpf.runtime.ArchDefinitions.*;
import static me.bechberger.ebpf.runtime.ArenaDefinitions.*;
import static me.bechberger.ebpf.runtime.ArpDefinitions.*;
import static me.bechberger.ebpf.runtime.ArrayDefinitions.*;
import static me.bechberger.ebpf.runtime.Asn1Definitions.*;
import static me.bechberger.ebpf.runtime.AssocDefinitions.*;
import static me.bechberger.ebpf.runtime.AsymmetricDefinitions.*;
import static me.bechberger.ebpf.runtime.AsyncDefinitions.*;
import static me.bechberger.ebpf.runtime.AtaDefinitions.*;
import static me.bechberger.ebpf.runtime.AtkbdDefinitions.*;
import static me.bechberger.ebpf.runtime.AtomicDefinitions.*;
import static me.bechberger.ebpf.runtime.AttachDefinitions.*;
import static me.bechberger.ebpf.runtime.AttributeDefinitions.*;
import static me.bechberger.ebpf.runtime.AuditDefinitions.*;
import static me.bechberger.ebpf.runtime.AuxiliaryDefinitions.*;
import static me.bechberger.ebpf.runtime.AvailableDefinitions.*;
import static me.bechberger.ebpf.runtime.AvcDefinitions.*;
import static me.bechberger.ebpf.runtime.AvtabDefinitions.*;
import static me.bechberger.ebpf.runtime.BackingDefinitions.*;
import static me.bechberger.ebpf.runtime.BacklightDefinitions.*;
import static me.bechberger.ebpf.runtime.BadDefinitions.*;
import static me.bechberger.ebpf.runtime.BadblocksDefinitions.*;
import static me.bechberger.ebpf.runtime.BalanceDefinitions.*;
import static me.bechberger.ebpf.runtime.BalloonDefinitions.*;
import static me.bechberger.ebpf.runtime.BdevDefinitions.*;
import static me.bechberger.ebpf.runtime.BdiDefinitions.*;
import static me.bechberger.ebpf.runtime.BgpioDefinitions.*;
import static me.bechberger.ebpf.runtime.BhDefinitions.*;
import static me.bechberger.ebpf.runtime.BindDefinitions.*;
import static me.bechberger.ebpf.runtime.BioDefinitions.*;
import static me.bechberger.ebpf.runtime.BitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.Blake2sDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkcgDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkdevDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkgDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkifDefinitions.*;
import static me.bechberger.ebpf.runtime.BlockDefinitions.*;
import static me.bechberger.ebpf.runtime.BloomDefinitions.*;
import static me.bechberger.ebpf.runtime.BootDefinitions.*;
import static me.bechberger.ebpf.runtime.BpfDefinitions.*;
import static me.bechberger.ebpf.runtime.BqlDefinitions.*;
import static me.bechberger.ebpf.runtime.BsgDefinitions.*;
import static me.bechberger.ebpf.runtime.BtfDefinitions.*;
import static me.bechberger.ebpf.runtime.BtreeDefinitions.*;
import static me.bechberger.ebpf.runtime.BtsDefinitions.*;
import static me.bechberger.ebpf.runtime.BufferDefinitions.*;
import static me.bechberger.ebpf.runtime.BuildDefinitions.*;
import static me.bechberger.ebpf.runtime.BusDefinitions.*;
import static me.bechberger.ebpf.runtime.BytDefinitions.*;
import static me.bechberger.ebpf.runtime.CacheDefinitions.*;
import static me.bechberger.ebpf.runtime.CalcDefinitions.*;
import static me.bechberger.ebpf.runtime.CalculateDefinitions.*;
import static me.bechberger.ebpf.runtime.CalipsoDefinitions.*;
import static me.bechberger.ebpf.runtime.CallDefinitions.*;
import static me.bechberger.ebpf.runtime.CanDefinitions.*;
import static me.bechberger.ebpf.runtime.CapDefinitions.*;
import static me.bechberger.ebpf.runtime.CcDefinitions.*;
import static me.bechberger.ebpf.runtime.CdevDefinitions.*;
import static me.bechberger.ebpf.runtime.CdromDefinitions.*;
import static me.bechberger.ebpf.runtime.CeaDefinitions.*;
import static me.bechberger.ebpf.runtime.Cfg80211Definitions.*;
import static me.bechberger.ebpf.runtime.Cgroup1Definitions.*;
import static me.bechberger.ebpf.runtime.CgroupDefinitions.*;
import static me.bechberger.ebpf.runtime.ChangeDefinitions.*;
import static me.bechberger.ebpf.runtime.ChargerDefinitions.*;
import static me.bechberger.ebpf.runtime.CheckDefinitions.*;
import static me.bechberger.ebpf.runtime.ChvDefinitions.*;
import static me.bechberger.ebpf.runtime.CipsoDefinitions.*;
import static me.bechberger.ebpf.runtime.ClassDefinitions.*;
import static me.bechberger.ebpf.runtime.CleanDefinitions.*;
import static me.bechberger.ebpf.runtime.CleanupDefinitions.*;
import static me.bechberger.ebpf.runtime.ClearDefinitions.*;
import static me.bechberger.ebpf.runtime.ClkDefinitions.*;
import static me.bechberger.ebpf.runtime.ClockeventsDefinitions.*;
import static me.bechberger.ebpf.runtime.ClocksourceDefinitions.*;
import static me.bechberger.ebpf.runtime.ClosureDefinitions.*;
import static me.bechberger.ebpf.runtime.CmaDefinitions.*;
import static me.bechberger.ebpf.runtime.CmciDefinitions.*;
import static me.bechberger.ebpf.runtime.CmdlineDefinitions.*;
import static me.bechberger.ebpf.runtime.CmisDefinitions.*;
import static me.bechberger.ebpf.runtime.CmosDefinitions.*;
import static me.bechberger.ebpf.runtime.CmpDefinitions.*;
import static me.bechberger.ebpf.runtime.CnDefinitions.*;
import static me.bechberger.ebpf.runtime.CollapseDefinitions.*;
import static me.bechberger.ebpf.runtime.CollectDefinitions.*;
import static me.bechberger.ebpf.runtime.CommonDefinitions.*;
import static me.bechberger.ebpf.runtime.CompactionDefinitions.*;
import static me.bechberger.ebpf.runtime.CompatDefinitions.*;
import static me.bechberger.ebpf.runtime.ComponentDefinitions.*;
import static me.bechberger.ebpf.runtime.ComputeDefinitions.*;
import static me.bechberger.ebpf.runtime.ConDefinitions.*;
import static me.bechberger.ebpf.runtime.CondDefinitions.*;
import static me.bechberger.ebpf.runtime.ConfigDefinitions.*;
import static me.bechberger.ebpf.runtime.ConfigfsDefinitions.*;
import static me.bechberger.ebpf.runtime.ConsoleDefinitions.*;
import static me.bechberger.ebpf.runtime.ContextDefinitions.*;
import static me.bechberger.ebpf.runtime.ConvertDefinitions.*;
import static me.bechberger.ebpf.runtime.CookieDefinitions.*;
import static me.bechberger.ebpf.runtime.CopyDefinitions.*;
import static me.bechberger.ebpf.runtime.CoreDefinitions.*;
import static me.bechberger.ebpf.runtime.CoredumpDefinitions.*;
import static me.bechberger.ebpf.runtime.CountDefinitions.*;
import static me.bechberger.ebpf.runtime.CpciDefinitions.*;
import static me.bechberger.ebpf.runtime.CperDefinitions.*;
import static me.bechberger.ebpf.runtime.CppcDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuacctDefinitions.*;
import static me.bechberger.ebpf.runtime.CpufreqDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuhpDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuidleDefinitions.*;
import static me.bechberger.ebpf.runtime.CpumaskDefinitions.*;
import static me.bechberger.ebpf.runtime.CpusDefinitions.*;
import static me.bechberger.ebpf.runtime.CpusetDefinitions.*;
import static me.bechberger.ebpf.runtime.CrashDefinitions.*;
import static me.bechberger.ebpf.runtime.CrbDefinitions.*;
import static me.bechberger.ebpf.runtime.Crc64Definitions.*;
import static me.bechberger.ebpf.runtime.CreateDefinitions.*;
import static me.bechberger.ebpf.runtime.CryptoDefinitions.*;
import static me.bechberger.ebpf.runtime.CrystalcoveDefinitions.*;
import static me.bechberger.ebpf.runtime.CssDefinitions.*;
import static me.bechberger.ebpf.runtime.CsumDefinitions.*;
import static me.bechberger.ebpf.runtime.CtDefinitions.*;
import static me.bechberger.ebpf.runtime.CtrlDefinitions.*;
import static me.bechberger.ebpf.runtime.CtxDefinitions.*;
import static me.bechberger.ebpf.runtime.CurrentDefinitions.*;
import static me.bechberger.ebpf.runtime.CxlDefinitions.*;
import static me.bechberger.ebpf.runtime.DDefinitions.*;
import static me.bechberger.ebpf.runtime.Da903xDefinitions.*;
import static me.bechberger.ebpf.runtime.Da9052Definitions.*;
import static me.bechberger.ebpf.runtime.Da9063Definitions.*;
import static me.bechberger.ebpf.runtime.DataDefinitions.*;
import static me.bechberger.ebpf.runtime.DaxDefinitions.*;
import static me.bechberger.ebpf.runtime.DbcDefinitions.*;
import static me.bechberger.ebpf.runtime.DbgDefinitions.*;
import static me.bechberger.ebpf.runtime.DcbDefinitions.*;
import static me.bechberger.ebpf.runtime.DcbnlDefinitions.*;
import static me.bechberger.ebpf.runtime.DdDefinitions.*;
import static me.bechberger.ebpf.runtime.DdebugDefinitions.*;
import static me.bechberger.ebpf.runtime.DeadlineDefinitions.*;
import static me.bechberger.ebpf.runtime.DebugDefinitions.*;
import static me.bechberger.ebpf.runtime.DebugfsDefinitions.*;
import static me.bechberger.ebpf.runtime.DecDefinitions.*;
import static me.bechberger.ebpf.runtime.DefaultDefinitions.*;
import static me.bechberger.ebpf.runtime.DeferredDefinitions.*;
import static me.bechberger.ebpf.runtime.DeflateDefinitions.*;
import static me.bechberger.ebpf.runtime.DelayacctDefinitions.*;
import static me.bechberger.ebpf.runtime.DelayedDefinitions.*;
import static me.bechberger.ebpf.runtime.DeleteDefinitions.*;
import static me.bechberger.ebpf.runtime.DentryDefinitions.*;
import static me.bechberger.ebpf.runtime.DequeueDefinitions.*;
import static me.bechberger.ebpf.runtime.DescDefinitions.*;
import static me.bechberger.ebpf.runtime.DestroyDefinitions.*;
import static me.bechberger.ebpf.runtime.DetachDefinitions.*;
import static me.bechberger.ebpf.runtime.DevDefinitions.*;
import static me.bechberger.ebpf.runtime.DevcdDefinitions.*;
import static me.bechberger.ebpf.runtime.DevfreqDefinitions.*;
import static me.bechberger.ebpf.runtime.DeviceDefinitions.*;
import static me.bechberger.ebpf.runtime.DevlDefinitions.*;
import static me.bechberger.ebpf.runtime.DevlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.DevmDefinitions.*;
import static me.bechberger.ebpf.runtime.DevptsDefinitions.*;
import static me.bechberger.ebpf.runtime.DevresDefinitions.*;
import static me.bechberger.ebpf.runtime.DhDefinitions.*;
import static me.bechberger.ebpf.runtime.DimDefinitions.*;
import static me.bechberger.ebpf.runtime.DisableDefinitions.*;
import static me.bechberger.ebpf.runtime.DiskDefinitions.*;
import static me.bechberger.ebpf.runtime.DispatchDefinitions.*;
import static me.bechberger.ebpf.runtime.DisplayidDefinitions.*;
import static me.bechberger.ebpf.runtime.DlDefinitions.*;
import static me.bechberger.ebpf.runtime.DmDefinitions.*;
import static me.bechberger.ebpf.runtime.DmaDefinitions.*;
import static me.bechberger.ebpf.runtime.DmabufDefinitions.*;
import static me.bechberger.ebpf.runtime.DmaengineDefinitions.*;
import static me.bechberger.ebpf.runtime.DmarDefinitions.*;
import static me.bechberger.ebpf.runtime.DmemDefinitions.*;
import static me.bechberger.ebpf.runtime.DmiDefinitions.*;
import static me.bechberger.ebpf.runtime.DnsDefinitions.*;
import static me.bechberger.ebpf.runtime.DoDefinitions.*;
import static me.bechberger.ebpf.runtime.DomainDefinitions.*;
import static me.bechberger.ebpf.runtime.DownDefinitions.*;
import static me.bechberger.ebpf.runtime.DpcDefinitions.*;
import static me.bechberger.ebpf.runtime.DpllDefinitions.*;
import static me.bechberger.ebpf.runtime.DpmDefinitions.*;
import static me.bechberger.ebpf.runtime.DquotDefinitions.*;
import static me.bechberger.ebpf.runtime.DrainDefinitions.*;
import static me.bechberger.ebpf.runtime.DrbgDefinitions.*;
import static me.bechberger.ebpf.runtime.DriverDefinitions.*;
import static me.bechberger.ebpf.runtime.DrmDefinitions.*;
import static me.bechberger.ebpf.runtime.DrmmDefinitions.*;
import static me.bechberger.ebpf.runtime.DropDefinitions.*;
import static me.bechberger.ebpf.runtime.DsaDefinitions.*;
import static me.bechberger.ebpf.runtime.DstDefinitions.*;
import static me.bechberger.ebpf.runtime.DummyDefinitions.*;
import static me.bechberger.ebpf.runtime.DummyconDefinitions.*;
import static me.bechberger.ebpf.runtime.DumpDefinitions.*;
import static me.bechberger.ebpf.runtime.DupDefinitions.*;
import static me.bechberger.ebpf.runtime.DvdDefinitions.*;
import static me.bechberger.ebpf.runtime.DwDefinitions.*;
import static me.bechberger.ebpf.runtime.Dwc2Definitions.*;
import static me.bechberger.ebpf.runtime.DxDefinitions.*;
import static me.bechberger.ebpf.runtime.DynDefinitions.*;
import static me.bechberger.ebpf.runtime.DyneventDefinitions.*;
import static me.bechberger.ebpf.runtime.EafnosupportDefinitions.*;
import static me.bechberger.ebpf.runtime.EarlyDefinitions.*;
import static me.bechberger.ebpf.runtime.EbitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.EcDefinitions.*;
import static me.bechberger.ebpf.runtime.EccDefinitions.*;
import static me.bechberger.ebpf.runtime.EcryptfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EdacDefinitions.*;
import static me.bechberger.ebpf.runtime.EddDefinitions.*;
import static me.bechberger.ebpf.runtime.EdidDefinitions.*;
import static me.bechberger.ebpf.runtime.EfiDefinitions.*;
import static me.bechberger.ebpf.runtime.EfivarDefinitions.*;
import static me.bechberger.ebpf.runtime.EfivarfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EhciDefinitions.*;
import static me.bechberger.ebpf.runtime.ElantsDefinitions.*;
import static me.bechberger.ebpf.runtime.ElevatorDefinitions.*;
import static me.bechberger.ebpf.runtime.ElfDefinitions.*;
import static me.bechberger.ebpf.runtime.ElvDefinitions.*;
import static me.bechberger.ebpf.runtime.EmDefinitions.*;
import static me.bechberger.ebpf.runtime.EmitDefinitions.*;
import static me.bechberger.ebpf.runtime.EnableDefinitions.*;
import static me.bechberger.ebpf.runtime.EndDefinitions.*;
import static me.bechberger.ebpf.runtime.EnqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.EpDefinitions.*;
import static me.bechberger.ebpf.runtime.EprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.ErstDefinitions.*;
import static me.bechberger.ebpf.runtime.EspintcpDefinitions.*;
import static me.bechberger.ebpf.runtime.EthDefinitions.*;
import static me.bechberger.ebpf.runtime.EthnlDefinitions.*;
import static me.bechberger.ebpf.runtime.EthtoolDefinitions.*;
import static me.bechberger.ebpf.runtime.EvdevDefinitions.*;
import static me.bechberger.ebpf.runtime.EventDefinitions.*;
import static me.bechberger.ebpf.runtime.EventfdDefinitions.*;
import static me.bechberger.ebpf.runtime.EventfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EvmDefinitions.*;
import static me.bechberger.ebpf.runtime.EvtchnDefinitions.*;
import static me.bechberger.ebpf.runtime.ExcDefinitions.*;
import static me.bechberger.ebpf.runtime.ExecmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ExitDefinitions.*;
import static me.bechberger.ebpf.runtime.Ext4Definitions.*;
import static me.bechberger.ebpf.runtime.ExtconDefinitions.*;
import static me.bechberger.ebpf.runtime.FDefinitions.*;
import static me.bechberger.ebpf.runtime.FanotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.FatDefinitions.*;
import static me.bechberger.ebpf.runtime.FaultDefinitions.*;
import static me.bechberger.ebpf.runtime.FauxDefinitions.*;
import static me.bechberger.ebpf.runtime.FbDefinitions.*;
import static me.bechberger.ebpf.runtime.FbconDefinitions.*;
import static me.bechberger.ebpf.runtime.FdtDefinitions.*;
import static me.bechberger.ebpf.runtime.FfDefinitions.*;
import static me.bechberger.ebpf.runtime.FgraphDefinitions.*;
import static me.bechberger.ebpf.runtime.Fib4Definitions.*;
import static me.bechberger.ebpf.runtime.Fib6Definitions.*;
import static me.bechberger.ebpf.runtime.FibDefinitions.*;
import static me.bechberger.ebpf.runtime.FifoDefinitions.*;
import static me.bechberger.ebpf.runtime.FileDefinitions.*;
import static me.bechberger.ebpf.runtime.FilemapDefinitions.*;
import static me.bechberger.ebpf.runtime.FilenameDefinitions.*;
import static me.bechberger.ebpf.runtime.FillDefinitions.*;
import static me.bechberger.ebpf.runtime.FilterDefinitions.*;
import static me.bechberger.ebpf.runtime.FindDefinitions.*;
import static me.bechberger.ebpf.runtime.FinishDefinitions.*;
import static me.bechberger.ebpf.runtime.FirmwareDefinitions.*;
import static me.bechberger.ebpf.runtime.FixedDefinitions.*;
import static me.bechberger.ebpf.runtime.FixupDefinitions.*;
import static me.bechberger.ebpf.runtime.FlowDefinitions.*;
import static me.bechberger.ebpf.runtime.FlushDefinitions.*;
import static me.bechberger.ebpf.runtime.FnDefinitions.*;
import static me.bechberger.ebpf.runtime.FolioDefinitions.*;
import static me.bechberger.ebpf.runtime.FollowDefinitions.*;
import static me.bechberger.ebpf.runtime.FopsDefinitions.*;
import static me.bechberger.ebpf.runtime.ForDefinitions.*;
import static me.bechberger.ebpf.runtime.ForceDefinitions.*;
import static me.bechberger.ebpf.runtime.FprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.FpuDefinitions.*;
import static me.bechberger.ebpf.runtime.FredDefinitions.*;
import static me.bechberger.ebpf.runtime.FreeDefinitions.*;
import static me.bechberger.ebpf.runtime.FreezeDefinitions.*;
import static me.bechberger.ebpf.runtime.FreezerDefinitions.*;
import static me.bechberger.ebpf.runtime.FreqDefinitions.*;
import static me.bechberger.ebpf.runtime.FromDefinitions.*;
import static me.bechberger.ebpf.runtime.FsDefinitions.*;
import static me.bechberger.ebpf.runtime.FscryptDefinitions.*;
import static me.bechberger.ebpf.runtime.FseDefinitions.*;
import static me.bechberger.ebpf.runtime.FsnotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.FsverityDefinitions.*;
import static me.bechberger.ebpf.runtime.FtraceDefinitions.*;
import static me.bechberger.ebpf.runtime.FullDefinitions.*;
import static me.bechberger.ebpf.runtime.FunctionDefinitions.*;
import static me.bechberger.ebpf.runtime.FuseDefinitions.*;
import static me.bechberger.ebpf.runtime.FutexDefinitions.*;
import static me.bechberger.ebpf.runtime.FwDefinitions.*;
import static me.bechberger.ebpf.runtime.FwnodeDefinitions.*;
import static me.bechberger.ebpf.runtime.GartDefinitions.*;
import static me.bechberger.ebpf.runtime.GcmDefinitions.*;
import static me.bechberger.ebpf.runtime.GenDefinitions.*;
import static me.bechberger.ebpf.runtime.GenericDefinitions.*;
import static me.bechberger.ebpf.runtime.GenlDefinitions.*;
import static me.bechberger.ebpf.runtime.GenpdDefinitions.*;
import static me.bechberger.ebpf.runtime.GenphyDefinitions.*;
import static me.bechberger.ebpf.runtime.GetDefinitions.*;
import static me.bechberger.ebpf.runtime.GhesDefinitions.*;
import static me.bechberger.ebpf.runtime.GnetDefinitions.*;
import static me.bechberger.ebpf.runtime.GnttabDefinitions.*;
import static me.bechberger.ebpf.runtime.GpioDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiochipDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiodDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiolibDefinitions.*;
import static me.bechberger.ebpf.runtime.GroDefinitions.*;
import static me.bechberger.ebpf.runtime.GroupDefinitions.*;
import static me.bechberger.ebpf.runtime.GupDefinitions.*;
import static me.bechberger.ebpf.runtime.HandleDefinitions.*;
import static me.bechberger.ebpf.runtime.HandshakeDefinitions.*;
import static me.bechberger.ebpf.runtime.HasDefinitions.*;
import static me.bechberger.ebpf.runtime.HashDefinitions.*;
import static me.bechberger.ebpf.runtime.HcdDefinitions.*;
import static me.bechberger.ebpf.runtime.HctxDefinitions.*;
import static me.bechberger.ebpf.runtime.HdmiDefinitions.*;
import static me.bechberger.ebpf.runtime.HfiDefinitions.*;
import static me.bechberger.ebpf.runtime.HidDefinitions.*;
import static me.bechberger.ebpf.runtime.HistDefinitions.*;
import static me.bechberger.ebpf.runtime.HmacDefinitions.*;
import static me.bechberger.ebpf.runtime.HmatDefinitions.*;
import static me.bechberger.ebpf.runtime.HmmDefinitions.*;
import static me.bechberger.ebpf.runtime.HookDefinitions.*;
import static me.bechberger.ebpf.runtime.HpetDefinitions.*;
import static me.bechberger.ebpf.runtime.HrtimerDefinitions.*;
import static me.bechberger.ebpf.runtime.HsuDefinitions.*;
import static me.bechberger.ebpf.runtime.HswepDefinitions.*;
import static me.bechberger.ebpf.runtime.HtabDefinitions.*;
import static me.bechberger.ebpf.runtime.HteDefinitions.*;
import static me.bechberger.ebpf.runtime.HubDefinitions.*;
import static me.bechberger.ebpf.runtime.HufDefinitions.*;
import static me.bechberger.ebpf.runtime.HugepageDefinitions.*;
import static me.bechberger.ebpf.runtime.HugetlbDefinitions.*;
import static me.bechberger.ebpf.runtime.HugetlbfsDefinitions.*;
import static me.bechberger.ebpf.runtime.HvDefinitions.*;
import static me.bechberger.ebpf.runtime.HvcDefinitions.*;
import static me.bechberger.ebpf.runtime.HwDefinitions.*;
import static me.bechberger.ebpf.runtime.HwlatDefinitions.*;
import static me.bechberger.ebpf.runtime.HwmonDefinitions.*;
import static me.bechberger.ebpf.runtime.HybridDefinitions.*;
import static me.bechberger.ebpf.runtime.HypervDefinitions.*;
import static me.bechberger.ebpf.runtime.HypervisorDefinitions.*;
import static me.bechberger.ebpf.runtime.I2cDefinitions.*;
import static me.bechberger.ebpf.runtime.I2cdevDefinitions.*;
import static me.bechberger.ebpf.runtime.I8042Definitions.*;
import static me.bechberger.ebpf.runtime.Ia32Definitions.*;
import static me.bechberger.ebpf.runtime.IbDefinitions.*;
import static me.bechberger.ebpf.runtime.IccDefinitions.*;
import static me.bechberger.ebpf.runtime.IcmpDefinitions.*;
import static me.bechberger.ebpf.runtime.Icmpv6Definitions.*;
import static me.bechberger.ebpf.runtime.IcxDefinitions.*;
import static me.bechberger.ebpf.runtime.IdleDefinitions.*;
import static me.bechberger.ebpf.runtime.IdrDefinitions.*;
import static me.bechberger.ebpf.runtime.Ieee80211Definitions.*;
import static me.bechberger.ebpf.runtime.IflaDefinitions.*;
import static me.bechberger.ebpf.runtime.Igmp6Definitions.*;
import static me.bechberger.ebpf.runtime.IgmpDefinitions.*;
import static me.bechberger.ebpf.runtime.ImaDefinitions.*;
import static me.bechberger.ebpf.runtime.ImsttfbDefinitions.*;
import static me.bechberger.ebpf.runtime.In6Definitions.*;
import static me.bechberger.ebpf.runtime.InDefinitions.*;
import static me.bechberger.ebpf.runtime.IncDefinitions.*;
import static me.bechberger.ebpf.runtime.Inet6Definitions.*;
import static me.bechberger.ebpf.runtime.InetDefinitions.*;
import static me.bechberger.ebpf.runtime.InitDefinitions.*;
import static me.bechberger.ebpf.runtime.InodeDefinitions.*;
import static me.bechberger.ebpf.runtime.InotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.InputDefinitions.*;
import static me.bechberger.ebpf.runtime.InsertDefinitions.*;
import static me.bechberger.ebpf.runtime.InsnDefinitions.*;
import static me.bechberger.ebpf.runtime.IntDefinitions.*;
import static me.bechberger.ebpf.runtime.IntegrityDefinitions.*;
import static me.bechberger.ebpf.runtime.IntelDefinitions.*;
import static me.bechberger.ebpf.runtime.IntervalDefinitions.*;
import static me.bechberger.ebpf.runtime.InvalidateDefinitions.*;
import static me.bechberger.ebpf.runtime.IoDefinitions.*;
import static me.bechberger.ebpf.runtime.Ioam6Definitions.*;
import static me.bechberger.ebpf.runtime.IoapicDefinitions.*;
import static me.bechberger.ebpf.runtime.IocDefinitions.*;
import static me.bechberger.ebpf.runtime.IocgDefinitions.*;
import static me.bechberger.ebpf.runtime.IoctlDefinitions.*;
import static me.bechberger.ebpf.runtime.IomapDefinitions.*;
import static me.bechberger.ebpf.runtime.IommuDefinitions.*;
import static me.bechberger.ebpf.runtime.IommufdDefinitions.*;
import static me.bechberger.ebpf.runtime.IopfDefinitions.*;
import static me.bechberger.ebpf.runtime.IoremapDefinitions.*;
import static me.bechberger.ebpf.runtime.IosfDefinitions.*;
import static me.bechberger.ebpf.runtime.IovDefinitions.*;
import static me.bechberger.ebpf.runtime.IovaDefinitions.*;
import static me.bechberger.ebpf.runtime.Ip4Definitions.*;
import static me.bechberger.ebpf.runtime.Ip6Definitions.*;
import static me.bechberger.ebpf.runtime.Ip6addrlblDefinitions.*;
import static me.bechberger.ebpf.runtime.Ip6mrDefinitions.*;
import static me.bechberger.ebpf.runtime.IpDefinitions.*;
import static me.bechberger.ebpf.runtime.IpcDefinitions.*;
import static me.bechberger.ebpf.runtime.IpeDefinitions.*;
import static me.bechberger.ebpf.runtime.IpmrDefinitions.*;
import static me.bechberger.ebpf.runtime.Ipv4Definitions.*;
import static me.bechberger.ebpf.runtime.Ipv6Definitions.*;
import static me.bechberger.ebpf.runtime.IrqDefinitions.*;
import static me.bechberger.ebpf.runtime.IrteDefinitions.*;
import static me.bechberger.ebpf.runtime.IsDefinitions.*;
import static me.bechberger.ebpf.runtime.IsaDefinitions.*;
import static me.bechberger.ebpf.runtime.IsolateDefinitions.*;
import static me.bechberger.ebpf.runtime.IterDefinitions.*;
import static me.bechberger.ebpf.runtime.IvbepDefinitions.*;
import static me.bechberger.ebpf.runtime.IwDefinitions.*;
import static me.bechberger.ebpf.runtime.JailhouseDefinitions.*;
import static me.bechberger.ebpf.runtime.Jbd2Definitions.*;
import static me.bechberger.ebpf.runtime.JentDefinitions.*;
import static me.bechberger.ebpf.runtime.JournalDefinitions.*;
import static me.bechberger.ebpf.runtime.JumpDefinitions.*;
import static me.bechberger.ebpf.runtime.KDefinitions.*;
import static me.bechberger.ebpf.runtime.KallsymsDefinitions.*;
import static me.bechberger.ebpf.runtime.KbdDefinitions.*;
import static me.bechberger.ebpf.runtime.KdbDefinitions.*;
import static me.bechberger.ebpf.runtime.KernDefinitions.*;
import static me.bechberger.ebpf.runtime.KernelDefinitions.*;
import static me.bechberger.ebpf.runtime.KernfsDefinitions.*;
import static me.bechberger.ebpf.runtime.KexecDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyctlDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyringDefinitions.*;
import static me.bechberger.ebpf.runtime.KfenceDefinitions.*;
import static me.bechberger.ebpf.runtime.KfifoDefinitions.*;
import static me.bechberger.ebpf.runtime.KfreeDefinitions.*;
import static me.bechberger.ebpf.runtime.KgdbDefinitions.*;
import static me.bechberger.ebpf.runtime.KgdbocDefinitions.*;
import static me.bechberger.ebpf.runtime.KhoDefinitions.*;
import static me.bechberger.ebpf.runtime.KillDefinitions.*;
import static me.bechberger.ebpf.runtime.KimageDefinitions.*;
import static me.bechberger.ebpf.runtime.KlistDefinitions.*;
import static me.bechberger.ebpf.runtime.KlpDefinitions.*;
import static me.bechberger.ebpf.runtime.KmallocDefinitions.*;
import static me.bechberger.ebpf.runtime.KmemDefinitions.*;
import static me.bechberger.ebpf.runtime.KmsgDefinitions.*;
import static me.bechberger.ebpf.runtime.KobjDefinitions.*;
import static me.bechberger.ebpf.runtime.KobjectDefinitions.*;
import static me.bechberger.ebpf.runtime.KprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.KsmDefinitions.*;
import static me.bechberger.ebpf.runtime.KsysDefinitions.*;
import static me.bechberger.ebpf.runtime.KthreadDefinitions.*;
import static me.bechberger.ebpf.runtime.KtimeDefinitions.*;
import static me.bechberger.ebpf.runtime.KvmDefinitions.*;
import static me.bechberger.ebpf.runtime.L3mdevDefinitions.*;
import static me.bechberger.ebpf.runtime.LabelDefinitions.*;
import static me.bechberger.ebpf.runtime.LandlockDefinitions.*;
import static me.bechberger.ebpf.runtime.LapicDefinitions.*;
import static me.bechberger.ebpf.runtime.LdmDefinitions.*;
import static me.bechberger.ebpf.runtime.LdmaDefinitions.*;
import static me.bechberger.ebpf.runtime.LedDefinitions.*;
import static me.bechberger.ebpf.runtime.LedtrigDefinitions.*;
import static me.bechberger.ebpf.runtime.LegacyDefinitions.*;
import static me.bechberger.ebpf.runtime.LinearDefinitions.*;
import static me.bechberger.ebpf.runtime.LineeventDefinitions.*;
import static me.bechberger.ebpf.runtime.LinereqDefinitions.*;
import static me.bechberger.ebpf.runtime.LinkDefinitions.*;
import static me.bechberger.ebpf.runtime.LinuxDefinitions.*;
import static me.bechberger.ebpf.runtime.ListDefinitions.*;
import static me.bechberger.ebpf.runtime.LoadDefinitions.*;
import static me.bechberger.ebpf.runtime.LocalDefinitions.*;
import static me.bechberger.ebpf.runtime.LockDefinitions.*;
import static me.bechberger.ebpf.runtime.LocksDefinitions.*;
import static me.bechberger.ebpf.runtime.LockupDefinitions.*;
import static me.bechberger.ebpf.runtime.LogDefinitions.*;
import static me.bechberger.ebpf.runtime.LookupDefinitions.*;
import static me.bechberger.ebpf.runtime.LoopDefinitions.*;
import static me.bechberger.ebpf.runtime.Lp8788Definitions.*;
import static me.bechberger.ebpf.runtime.LpssDefinitions.*;
import static me.bechberger.ebpf.runtime.LruDefinitions.*;
import static me.bechberger.ebpf.runtime.LskcipherDefinitions.*;
import static me.bechberger.ebpf.runtime.LsmDefinitions.*;
import static me.bechberger.ebpf.runtime.LwtunnelDefinitions.*;
import static me.bechberger.ebpf.runtime.Lz4Definitions.*;
import static me.bechberger.ebpf.runtime.MachineDefinitions.*;
import static me.bechberger.ebpf.runtime.MacsecDefinitions.*;
import static me.bechberger.ebpf.runtime.MadviseDefinitions.*;
import static me.bechberger.ebpf.runtime.MakeDefinitions.*;
import static me.bechberger.ebpf.runtime.MapDefinitions.*;
import static me.bechberger.ebpf.runtime.MapleDefinitions.*;
import static me.bechberger.ebpf.runtime.MarkDefinitions.*;
import static me.bechberger.ebpf.runtime.MasDefinitions.*;
import static me.bechberger.ebpf.runtime.MatchDefinitions.*;
import static me.bechberger.ebpf.runtime.Max310xDefinitions.*;
import static me.bechberger.ebpf.runtime.Max77693Definitions.*;
import static me.bechberger.ebpf.runtime.Max8925Definitions.*;
import static me.bechberger.ebpf.runtime.Max8997Definitions.*;
import static me.bechberger.ebpf.runtime.Max8998Definitions.*;
import static me.bechberger.ebpf.runtime.MaxDefinitions.*;
import static me.bechberger.ebpf.runtime.MayDefinitions.*;
import static me.bechberger.ebpf.runtime.MaybeDefinitions.*;
import static me.bechberger.ebpf.runtime.MbDefinitions.*;
import static me.bechberger.ebpf.runtime.MbmDefinitions.*;
import static me.bechberger.ebpf.runtime.MboxDefinitions.*;
import static me.bechberger.ebpf.runtime.MceDefinitions.*;
import static me.bechberger.ebpf.runtime.McheckDefinitions.*;
import static me.bechberger.ebpf.runtime.MciDefinitions.*;
import static me.bechberger.ebpf.runtime.MctpDefinitions.*;
import static me.bechberger.ebpf.runtime.MctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.MdDefinitions.*;
import static me.bechberger.ebpf.runtime.MddevDefinitions.*;
import static me.bechberger.ebpf.runtime.MdioDefinitions.*;
import static me.bechberger.ebpf.runtime.MdiobusDefinitions.*;
import static me.bechberger.ebpf.runtime.MemDefinitions.*;
import static me.bechberger.ebpf.runtime.MemblockDefinitions.*;
import static me.bechberger.ebpf.runtime.MemcgDefinitions.*;
import static me.bechberger.ebpf.runtime.MemcpyDefinitions.*;
import static me.bechberger.ebpf.runtime.MemmapDefinitions.*;
import static me.bechberger.ebpf.runtime.MemoryDefinitions.*;
import static me.bechberger.ebpf.runtime.MempoolDefinitions.*;
import static me.bechberger.ebpf.runtime.MemtypeDefinitions.*;
import static me.bechberger.ebpf.runtime.MigrateDefinitions.*;
import static me.bechberger.ebpf.runtime.MinDefinitions.*;
import static me.bechberger.ebpf.runtime.MipiDefinitions.*;
import static me.bechberger.ebpf.runtime.MiscDefinitions.*;
import static me.bechberger.ebpf.runtime.MldDefinitions.*;
import static me.bechberger.ebpf.runtime.MlsDefinitions.*;
import static me.bechberger.ebpf.runtime.MmDefinitions.*;
import static me.bechberger.ebpf.runtime.MmapDefinitions.*;
import static me.bechberger.ebpf.runtime.MmcDefinitions.*;
import static me.bechberger.ebpf.runtime.MmioDefinitions.*;
import static me.bechberger.ebpf.runtime.MmuDefinitions.*;
import static me.bechberger.ebpf.runtime.MntDefinitions.*;
import static me.bechberger.ebpf.runtime.ModDefinitions.*;
import static me.bechberger.ebpf.runtime.ModuleDefinitions.*;
import static me.bechberger.ebpf.runtime.MountDefinitions.*;
import static me.bechberger.ebpf.runtime.MousedevDefinitions.*;
import static me.bechberger.ebpf.runtime.MoveDefinitions.*;
import static me.bechberger.ebpf.runtime.MpDefinitions.*;
import static me.bechberger.ebpf.runtime.MpageDefinitions.*;
import static me.bechberger.ebpf.runtime.MpiDefinitions.*;
import static me.bechberger.ebpf.runtime.MpihelpDefinitions.*;
import static me.bechberger.ebpf.runtime.MpolDefinitions.*;
import static me.bechberger.ebpf.runtime.MptcpDefinitions.*;
import static me.bechberger.ebpf.runtime.MqDefinitions.*;
import static me.bechberger.ebpf.runtime.MqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.MrDefinitions.*;
import static me.bechberger.ebpf.runtime.MsgDefinitions.*;
import static me.bechberger.ebpf.runtime.MsiDefinitions.*;
import static me.bechberger.ebpf.runtime.MsrDefinitions.*;
import static me.bechberger.ebpf.runtime.MtDefinitions.*;
import static me.bechberger.ebpf.runtime.MtreeDefinitions.*;
import static me.bechberger.ebpf.runtime.MtrrDefinitions.*;
import static me.bechberger.ebpf.runtime.MutexDefinitions.*;
import static me.bechberger.ebpf.runtime.NDefinitions.*;
import static me.bechberger.ebpf.runtime.NapiDefinitions.*;
import static me.bechberger.ebpf.runtime.NativeDefinitions.*;
import static me.bechberger.ebpf.runtime.NbconDefinitions.*;
import static me.bechberger.ebpf.runtime.NcsiDefinitions.*;
import static me.bechberger.ebpf.runtime.NdDefinitions.*;
import static me.bechberger.ebpf.runtime.NdiscDefinitions.*;
import static me.bechberger.ebpf.runtime.NeighDefinitions.*;
import static me.bechberger.ebpf.runtime.NetDefinitions.*;
import static me.bechberger.ebpf.runtime.NetdevDefinitions.*;
import static me.bechberger.ebpf.runtime.NetifDefinitions.*;
import static me.bechberger.ebpf.runtime.NetkitDefinitions.*;
import static me.bechberger.ebpf.runtime.NetlblDefinitions.*;
import static me.bechberger.ebpf.runtime.NetlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.NetnsDefinitions.*;
import static me.bechberger.ebpf.runtime.NetpollDefinitions.*;
import static me.bechberger.ebpf.runtime.NewDefinitions.*;
import static me.bechberger.ebpf.runtime.NextDefinitions.*;
import static me.bechberger.ebpf.runtime.NexthopDefinitions.*;
import static me.bechberger.ebpf.runtime.NfDefinitions.*;
import static me.bechberger.ebpf.runtime.Nfs4Definitions.*;
import static me.bechberger.ebpf.runtime.NfsDefinitions.*;
import static me.bechberger.ebpf.runtime.NhDefinitions.*;
import static me.bechberger.ebpf.runtime.NhmexDefinitions.*;
import static me.bechberger.ebpf.runtime.Nl80211Definitions.*;
import static me.bechberger.ebpf.runtime.NlaDefinitions.*;
import static me.bechberger.ebpf.runtime.NmiDefinitions.*;
import static me.bechberger.ebpf.runtime.NoDefinitions.*;
import static me.bechberger.ebpf.runtime.NodeDefinitions.*;
import static me.bechberger.ebpf.runtime.NoopDefinitions.*;
import static me.bechberger.ebpf.runtime.NotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.NrDefinitions.*;
import static me.bechberger.ebpf.runtime.NsDefinitions.*;
import static me.bechberger.ebpf.runtime.NullDefinitions.*;
import static me.bechberger.ebpf.runtime.NumaDefinitions.*;
import static me.bechberger.ebpf.runtime.NumachipDefinitions.*;
import static me.bechberger.ebpf.runtime.NvdimmDefinitions.*;
import static me.bechberger.ebpf.runtime.NvmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ObjDefinitions.*;
import static me.bechberger.ebpf.runtime.OctepDefinitions.*;
import static me.bechberger.ebpf.runtime.OdDefinitions.*;
import static me.bechberger.ebpf.runtime.OfDefinitions.*;
import static me.bechberger.ebpf.runtime.OhciDefinitions.*;
import static me.bechberger.ebpf.runtime.OldDefinitions.*;
import static me.bechberger.ebpf.runtime.OomDefinitions.*;
import static me.bechberger.ebpf.runtime.OpalDefinitions.*;
import static me.bechberger.ebpf.runtime.OpenDefinitions.*;
import static me.bechberger.ebpf.runtime.OppDefinitions.*;
import static me.bechberger.ebpf.runtime.OsnoiseDefinitions.*;
import static me.bechberger.ebpf.runtime.P4Definitions.*;
import static me.bechberger.ebpf.runtime.PacketDefinitions.*;
import static me.bechberger.ebpf.runtime.PadataDefinitions.*;
import static me.bechberger.ebpf.runtime.PageDefinitions.*;
import static me.bechberger.ebpf.runtime.PagemapDefinitions.*;
import static me.bechberger.ebpf.runtime.PagesDefinitions.*;
import static me.bechberger.ebpf.runtime.PalmasDefinitions.*;
import static me.bechberger.ebpf.runtime.PanelDefinitions.*;
import static me.bechberger.ebpf.runtime.ParamDefinitions.*;
import static me.bechberger.ebpf.runtime.ParseDefinitions.*;
import static me.bechberger.ebpf.runtime.PartDefinitions.*;
import static me.bechberger.ebpf.runtime.PathDefinitions.*;
import static me.bechberger.ebpf.runtime.PcapDefinitions.*;
import static me.bechberger.ebpf.runtime.PccDefinitions.*;
import static me.bechberger.ebpf.runtime.PciDefinitions.*;
import static me.bechberger.ebpf.runtime.PcibiosDefinitions.*;
import static me.bechberger.ebpf.runtime.PcieDefinitions.*;
import static me.bechberger.ebpf.runtime.PciehpDefinitions.*;
import static me.bechberger.ebpf.runtime.PcimDefinitions.*;
import static me.bechberger.ebpf.runtime.PcpuDefinitions.*;
import static me.bechberger.ebpf.runtime.PercpuDefinitions.*;
import static me.bechberger.ebpf.runtime.PerfDefinitions.*;
import static me.bechberger.ebpf.runtime.PfifoDefinitions.*;
import static me.bechberger.ebpf.runtime.PfnDefinitions.*;
import static me.bechberger.ebpf.runtime.PhyDefinitions.*;
import static me.bechberger.ebpf.runtime.PhysDefinitions.*;
import static me.bechberger.ebpf.runtime.PhysdevDefinitions.*;
import static me.bechberger.ebpf.runtime.PickDefinitions.*;
import static me.bechberger.ebpf.runtime.PidDefinitions.*;
import static me.bechberger.ebpf.runtime.PidfsDefinitions.*;
import static me.bechberger.ebpf.runtime.PidsDefinitions.*;
import static me.bechberger.ebpf.runtime.PiixDefinitions.*;
import static me.bechberger.ebpf.runtime.PinDefinitions.*;
import static me.bechberger.ebpf.runtime.PinconfDefinitions.*;
import static me.bechberger.ebpf.runtime.PinctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.PingDefinitions.*;
import static me.bechberger.ebpf.runtime.PinmuxDefinitions.*;
import static me.bechberger.ebpf.runtime.PipeDefinitions.*;
import static me.bechberger.ebpf.runtime.PirqDefinitions.*;
import static me.bechberger.ebpf.runtime.Pkcs1padDefinitions.*;
import static me.bechberger.ebpf.runtime.Pkcs7Definitions.*;
import static me.bechberger.ebpf.runtime.PlatformDefinitions.*;
import static me.bechberger.ebpf.runtime.PldmfwDefinitions.*;
import static me.bechberger.ebpf.runtime.Pm860xDefinitions.*;
import static me.bechberger.ebpf.runtime.PmDefinitions.*;
import static me.bechberger.ebpf.runtime.PmcDefinitions.*;
import static me.bechberger.ebpf.runtime.PmdDefinitions.*;
import static me.bechberger.ebpf.runtime.PmuDefinitions.*;
import static me.bechberger.ebpf.runtime.PnpDefinitions.*;
import static me.bechberger.ebpf.runtime.PnpacpiDefinitions.*;
import static me.bechberger.ebpf.runtime.PolicyDefinitions.*;
import static me.bechberger.ebpf.runtime.PolicydbDefinitions.*;
import static me.bechberger.ebpf.runtime.PollDefinitions.*;
import static me.bechberger.ebpf.runtime.Poly1305Definitions.*;
import static me.bechberger.ebpf.runtime.PopulateDefinitions.*;
import static me.bechberger.ebpf.runtime.PortDefinitions.*;
import static me.bechberger.ebpf.runtime.PosixDefinitions.*;
import static me.bechberger.ebpf.runtime.PowerDefinitions.*;
import static me.bechberger.ebpf.runtime.PowercapDefinitions.*;
import static me.bechberger.ebpf.runtime.PppDefinitions.*;
import static me.bechberger.ebpf.runtime.PpsDefinitions.*;
import static me.bechberger.ebpf.runtime.PrDefinitions.*;
import static me.bechberger.ebpf.runtime.PrbDefinitions.*;
import static me.bechberger.ebpf.runtime.PreemptDefinitions.*;
import static me.bechberger.ebpf.runtime.PrepareDefinitions.*;
import static me.bechberger.ebpf.runtime.PrintDefinitions.*;
import static me.bechberger.ebpf.runtime.PrintkDefinitions.*;
import static me.bechberger.ebpf.runtime.ProbeDefinitions.*;
import static me.bechberger.ebpf.runtime.ProbestubDefinitions.*;
import static me.bechberger.ebpf.runtime.ProcDefinitions.*;
import static me.bechberger.ebpf.runtime.ProcessDefinitions.*;
import static me.bechberger.ebpf.runtime.ProfileDefinitions.*;
import static me.bechberger.ebpf.runtime.ProgDefinitions.*;
import static me.bechberger.ebpf.runtime.PropagateDefinitions.*;
import static me.bechberger.ebpf.runtime.ProtoDefinitions.*;
import static me.bechberger.ebpf.runtime.Ps2Definitions.*;
import static me.bechberger.ebpf.runtime.PseDefinitions.*;
import static me.bechberger.ebpf.runtime.PseudoDefinitions.*;
import static me.bechberger.ebpf.runtime.PsiDefinitions.*;
import static me.bechberger.ebpf.runtime.PskbDefinitions.*;
import static me.bechberger.ebpf.runtime.PstoreDefinitions.*;
import static me.bechberger.ebpf.runtime.PtDefinitions.*;
import static me.bechberger.ebpf.runtime.PtdumpDefinitions.*;
import static me.bechberger.ebpf.runtime.PteDefinitions.*;
import static me.bechberger.ebpf.runtime.PtiDefinitions.*;
import static me.bechberger.ebpf.runtime.PtpDefinitions.*;
import static me.bechberger.ebpf.runtime.PtraceDefinitions.*;
import static me.bechberger.ebpf.runtime.PtyDefinitions.*;
import static me.bechberger.ebpf.runtime.PushDefinitions.*;
import static me.bechberger.ebpf.runtime.PutDefinitions.*;
import static me.bechberger.ebpf.runtime.PvDefinitions.*;
import static me.bechberger.ebpf.runtime.PvclockDefinitions.*;
import static me.bechberger.ebpf.runtime.PwmDefinitions.*;
import static me.bechberger.ebpf.runtime.QdiscDefinitions.*;
import static me.bechberger.ebpf.runtime.QhDefinitions.*;
import static me.bechberger.ebpf.runtime.QiDefinitions.*;
import static me.bechberger.ebpf.runtime.QueueDefinitions.*;
import static me.bechberger.ebpf.runtime.QuirkDefinitions.*;
import static me.bechberger.ebpf.runtime.QuotaDefinitions.*;
import static me.bechberger.ebpf.runtime.RadixDefinitions.*;
import static me.bechberger.ebpf.runtime.RamfsDefinitions.*;
import static me.bechberger.ebpf.runtime.RandomDefinitions.*;
import static me.bechberger.ebpf.runtime.RangeDefinitions.*;
import static me.bechberger.ebpf.runtime.Raw6Definitions.*;
import static me.bechberger.ebpf.runtime.RawDefinitions.*;
import static me.bechberger.ebpf.runtime.Rawv6Definitions.*;
import static me.bechberger.ebpf.runtime.RbDefinitions.*;
import static me.bechberger.ebpf.runtime.Rc5t583Definitions.*;
import static me.bechberger.ebpf.runtime.RcuDefinitions.*;
import static me.bechberger.ebpf.runtime.RdevDefinitions.*;
import static me.bechberger.ebpf.runtime.RdmaDefinitions.*;
import static me.bechberger.ebpf.runtime.RdmacgDefinitions.*;
import static me.bechberger.ebpf.runtime.RdtDefinitions.*;
import static me.bechberger.ebpf.runtime.RdtgroupDefinitions.*;
import static me.bechberger.ebpf.runtime.ReadDefinitions.*;
import static me.bechberger.ebpf.runtime.ReclaimDefinitions.*;
import static me.bechberger.ebpf.runtime.RegDefinitions.*;
import static me.bechberger.ebpf.runtime.RegcacheDefinitions.*;
import static me.bechberger.ebpf.runtime.RegisterDefinitions.*;
import static me.bechberger.ebpf.runtime.RegmapDefinitions.*;
import static me.bechberger.ebpf.runtime.RegulatorDefinitions.*;
import static me.bechberger.ebpf.runtime.RelayDefinitions.*;
import static me.bechberger.ebpf.runtime.ReleaseDefinitions.*;
import static me.bechberger.ebpf.runtime.RemapDefinitions.*;
import static me.bechberger.ebpf.runtime.RemoveDefinitions.*;
import static me.bechberger.ebpf.runtime.ReplaceDefinitions.*;
import static me.bechberger.ebpf.runtime.ReportDefinitions.*;
import static me.bechberger.ebpf.runtime.RequestDefinitions.*;
import static me.bechberger.ebpf.runtime.ResctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.ReserveDefinitions.*;
import static me.bechberger.ebpf.runtime.ResetDefinitions.*;
import static me.bechberger.ebpf.runtime.ResourceDefinitions.*;
import static me.bechberger.ebpf.runtime.RestoreDefinitions.*;
import static me.bechberger.ebpf.runtime.RestrictDefinitions.*;
import static me.bechberger.ebpf.runtime.ResumeDefinitions.*;
import static me.bechberger.ebpf.runtime.RethookDefinitions.*;
import static me.bechberger.ebpf.runtime.ReuseportDefinitions.*;
import static me.bechberger.ebpf.runtime.RfkillDefinitions.*;
import static me.bechberger.ebpf.runtime.RhashtableDefinitions.*;
import static me.bechberger.ebpf.runtime.RingDefinitions.*;
import static me.bechberger.ebpf.runtime.RingbufDefinitions.*;
import static me.bechberger.ebpf.runtime.RioDefinitions.*;
import static me.bechberger.ebpf.runtime.RngDefinitions.*;
import static me.bechberger.ebpf.runtime.RoleDefinitions.*;
import static me.bechberger.ebpf.runtime.RpcDefinitions.*;
import static me.bechberger.ebpf.runtime.RpmDefinitions.*;
import static me.bechberger.ebpf.runtime.RprocDefinitions.*;
import static me.bechberger.ebpf.runtime.RqDefinitions.*;
import static me.bechberger.ebpf.runtime.RsaDefinitions.*;
import static me.bechberger.ebpf.runtime.RsassaDefinitions.*;
import static me.bechberger.ebpf.runtime.RseqDefinitions.*;
import static me.bechberger.ebpf.runtime.RssDefinitions.*;
import static me.bechberger.ebpf.runtime.Rt6Definitions.*;
import static me.bechberger.ebpf.runtime.RtDefinitions.*;
import static me.bechberger.ebpf.runtime.RtcDefinitions.*;
import static me.bechberger.ebpf.runtime.RtmDefinitions.*;
import static me.bechberger.ebpf.runtime.RtnetlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.RtnlDefinitions.*;
import static me.bechberger.ebpf.runtime.RunDefinitions.*;
import static me.bechberger.ebpf.runtime.RustDefinitions.*;
import static me.bechberger.ebpf.runtime.RvDefinitions.*;
import static me.bechberger.ebpf.runtime.RxDefinitions.*;
import static me.bechberger.ebpf.runtime.SDefinitions.*;
import static me.bechberger.ebpf.runtime.SataDefinitions.*;
import static me.bechberger.ebpf.runtime.SaveDefinitions.*;
import static me.bechberger.ebpf.runtime.SavedDefinitions.*;
import static me.bechberger.ebpf.runtime.SbitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.ScanDefinitions.*;
import static me.bechberger.ebpf.runtime.SccnxpDefinitions.*;
import static me.bechberger.ebpf.runtime.SchedDefinitions.*;
import static me.bechberger.ebpf.runtime.ScheduleDefinitions.*;
import static me.bechberger.ebpf.runtime.ScmDefinitions.*;
import static me.bechberger.ebpf.runtime.ScsiDefinitions.*;
import static me.bechberger.ebpf.runtime.SctpDefinitions.*;
import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.SdDefinitions.*;
import static me.bechberger.ebpf.runtime.SdevDefinitions.*;
import static me.bechberger.ebpf.runtime.SdioDefinitions.*;
import static me.bechberger.ebpf.runtime.SeccompDefinitions.*;
import static me.bechberger.ebpf.runtime.SecurityDefinitions.*;
import static me.bechberger.ebpf.runtime.Seg6Definitions.*;
import static me.bechberger.ebpf.runtime.SelDefinitions.*;
import static me.bechberger.ebpf.runtime.SelectDefinitions.*;
import static me.bechberger.ebpf.runtime.SelinuxDefinitions.*;
import static me.bechberger.ebpf.runtime.SendDefinitions.*;
import static me.bechberger.ebpf.runtime.SeqDefinitions.*;
import static me.bechberger.ebpf.runtime.SerdevDefinitions.*;
import static me.bechberger.ebpf.runtime.Serial8250Definitions.*;
import static me.bechberger.ebpf.runtime.SerialDefinitions.*;
import static me.bechberger.ebpf.runtime.SerioDefinitions.*;
import static me.bechberger.ebpf.runtime.SetDefinitions.*;
import static me.bechberger.ebpf.runtime.SetupDefinitions.*;
import static me.bechberger.ebpf.runtime.SevDefinitions.*;
import static me.bechberger.ebpf.runtime.SfpDefinitions.*;
import static me.bechberger.ebpf.runtime.SgDefinitions.*;
import static me.bechberger.ebpf.runtime.SgxDefinitions.*;
import static me.bechberger.ebpf.runtime.Sha1Definitions.*;
import static me.bechberger.ebpf.runtime.Sha256Definitions.*;
import static me.bechberger.ebpf.runtime.Sha512Definitions.*;
import static me.bechberger.ebpf.runtime.ShashDefinitions.*;
import static me.bechberger.ebpf.runtime.ShmDefinitions.*;
import static me.bechberger.ebpf.runtime.ShmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ShouldDefinitions.*;
import static me.bechberger.ebpf.runtime.ShowDefinitions.*;
import static me.bechberger.ebpf.runtime.ShpchpDefinitions.*;
import static me.bechberger.ebpf.runtime.ShrinkDefinitions.*;
import static me.bechberger.ebpf.runtime.SidtabDefinitions.*;
import static me.bechberger.ebpf.runtime.SimpleDefinitions.*;
import static me.bechberger.ebpf.runtime.SingleDefinitions.*;
import static me.bechberger.ebpf.runtime.SisDefinitions.*;
import static me.bechberger.ebpf.runtime.SkDefinitions.*;
import static me.bechberger.ebpf.runtime.SkcipherDefinitions.*;
import static me.bechberger.ebpf.runtime.SkxDefinitions.*;
import static me.bechberger.ebpf.runtime.SlabDefinitions.*;
import static me.bechberger.ebpf.runtime.SmackDefinitions.*;
import static me.bechberger.ebpf.runtime.SmeDefinitions.*;
import static me.bechberger.ebpf.runtime.SmkDefinitions.*;
import static me.bechberger.ebpf.runtime.SmpDefinitions.*;
import static me.bechberger.ebpf.runtime.SnapshotDefinitions.*;
import static me.bechberger.ebpf.runtime.SnbDefinitions.*;
import static me.bechberger.ebpf.runtime.SnbepDefinitions.*;
import static me.bechberger.ebpf.runtime.SnpDefinitions.*;
import static me.bechberger.ebpf.runtime.SnrDefinitions.*;
import static me.bechberger.ebpf.runtime.SocDefinitions.*;
import static me.bechberger.ebpf.runtime.SockDefinitions.*;
import static me.bechberger.ebpf.runtime.SoftwareDefinitions.*;
import static me.bechberger.ebpf.runtime.SparseDefinitions.*;
import static me.bechberger.ebpf.runtime.SpiDefinitions.*;
import static me.bechberger.ebpf.runtime.SpliceDefinitions.*;
import static me.bechberger.ebpf.runtime.SplitDefinitions.*;
import static me.bechberger.ebpf.runtime.SprDefinitions.*;
import static me.bechberger.ebpf.runtime.SquashfsDefinitions.*;
import static me.bechberger.ebpf.runtime.SrDefinitions.*;
import static me.bechberger.ebpf.runtime.SramDefinitions.*;
import static me.bechberger.ebpf.runtime.SrcuDefinitions.*;
import static me.bechberger.ebpf.runtime.SriovDefinitions.*;
import static me.bechberger.ebpf.runtime.StackDefinitions.*;
import static me.bechberger.ebpf.runtime.StartDefinitions.*;
import static me.bechberger.ebpf.runtime.StatDefinitions.*;
import static me.bechberger.ebpf.runtime.StaticDefinitions.*;
import static me.bechberger.ebpf.runtime.StatsDefinitions.*;
import static me.bechberger.ebpf.runtime.StopDefinitions.*;
import static me.bechberger.ebpf.runtime.StoreDefinitions.*;
import static me.bechberger.ebpf.runtime.StripeDefinitions.*;
import static me.bechberger.ebpf.runtime.StrpDefinitions.*;
import static me.bechberger.ebpf.runtime.SubflowDefinitions.*;
import static me.bechberger.ebpf.runtime.SubmitDefinitions.*;
import static me.bechberger.ebpf.runtime.SugovDefinitions.*;
import static me.bechberger.ebpf.runtime.SuperDefinitions.*;
import static me.bechberger.ebpf.runtime.SuspendDefinitions.*;
import static me.bechberger.ebpf.runtime.SvcDefinitions.*;
import static me.bechberger.ebpf.runtime.SvsmDefinitions.*;
import static me.bechberger.ebpf.runtime.SwDefinitions.*;
import static me.bechberger.ebpf.runtime.SwapDefinitions.*;
import static me.bechberger.ebpf.runtime.SwiotlbDefinitions.*;
import static me.bechberger.ebpf.runtime.SwitchDefinitions.*;
import static me.bechberger.ebpf.runtime.SwitchdevDefinitions.*;
import static me.bechberger.ebpf.runtime.SwsuspDefinitions.*;
import static me.bechberger.ebpf.runtime.Sx150xDefinitions.*;
import static me.bechberger.ebpf.runtime.SyncDefinitions.*;
import static me.bechberger.ebpf.runtime.SynchronizeDefinitions.*;
import static me.bechberger.ebpf.runtime.SynthDefinitions.*;
import static me.bechberger.ebpf.runtime.SysDefinitions.*;
import static me.bechberger.ebpf.runtime.SyscallDefinitions.*;
import static me.bechberger.ebpf.runtime.SysctlDefinitions.*;
import static me.bechberger.ebpf.runtime.SysfsDefinitions.*;
import static me.bechberger.ebpf.runtime.SysrqDefinitions.*;
import static me.bechberger.ebpf.runtime.SystemDefinitions.*;
import static me.bechberger.ebpf.runtime.SysvecDefinitions.*;
import static me.bechberger.ebpf.runtime.TargetDefinitions.*;
import static me.bechberger.ebpf.runtime.TaskDefinitions.*;
import static me.bechberger.ebpf.runtime.TaskletDefinitions.*;
import static me.bechberger.ebpf.runtime.TbootDefinitions.*;
import static me.bechberger.ebpf.runtime.TcDefinitions.*;
import static me.bechberger.ebpf.runtime.TcfDefinitions.*;
import static me.bechberger.ebpf.runtime.TcpDefinitions.*;
import static me.bechberger.ebpf.runtime.TcxDefinitions.*;
import static me.bechberger.ebpf.runtime.TdhDefinitions.*;
import static me.bechberger.ebpf.runtime.TdxDefinitions.*;
import static me.bechberger.ebpf.runtime.TestDefinitions.*;
import static me.bechberger.ebpf.runtime.TextDefinitions.*;
import static me.bechberger.ebpf.runtime.TgDefinitions.*;
import static me.bechberger.ebpf.runtime.ThermalDefinitions.*;
import static me.bechberger.ebpf.runtime.ThreadDefinitions.*;
import static me.bechberger.ebpf.runtime.ThrotlDefinitions.*;
import static me.bechberger.ebpf.runtime.TickDefinitions.*;
import static me.bechberger.ebpf.runtime.TimekeepingDefinitions.*;
import static me.bechberger.ebpf.runtime.TimensDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerfdDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerlatDefinitions.*;
import static me.bechberger.ebpf.runtime.TkDefinitions.*;
import static me.bechberger.ebpf.runtime.TlbDefinitions.*;
import static me.bechberger.ebpf.runtime.TlsDefinitions.*;
import static me.bechberger.ebpf.runtime.TmigrDefinitions.*;
import static me.bechberger.ebpf.runtime.TnumDefinitions.*;
import static me.bechberger.ebpf.runtime.ToDefinitions.*;
import static me.bechberger.ebpf.runtime.TomoyoDefinitions.*;
import static me.bechberger.ebpf.runtime.TopologyDefinitions.*;
import static me.bechberger.ebpf.runtime.TouchDefinitions.*;
import static me.bechberger.ebpf.runtime.TpacketDefinitions.*;
import static me.bechberger.ebpf.runtime.Tpm1Definitions.*;
import static me.bechberger.ebpf.runtime.Tpm2Definitions.*;
import static me.bechberger.ebpf.runtime.TpmDefinitions.*;
import static me.bechberger.ebpf.runtime.Tps6586xDefinitions.*;
import static me.bechberger.ebpf.runtime.Tps65910Definitions.*;
import static me.bechberger.ebpf.runtime.TraceDefinitions.*;
import static me.bechberger.ebpf.runtime.TracefsDefinitions.*;
import static me.bechberger.ebpf.runtime.TraceiterDefinitions.*;
import static me.bechberger.ebpf.runtime.TracepointDefinitions.*;
import static me.bechberger.ebpf.runtime.TraceprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.TracerDefinitions.*;
import static me.bechberger.ebpf.runtime.TracingDefinitions.*;
import static me.bechberger.ebpf.runtime.TransportDefinitions.*;
import static me.bechberger.ebpf.runtime.TrieDefinitions.*;
import static me.bechberger.ebpf.runtime.TruncateDefinitions.*;
import static me.bechberger.ebpf.runtime.TrustedDefinitions.*;
import static me.bechberger.ebpf.runtime.TryDefinitions.*;
import static me.bechberger.ebpf.runtime.TscDefinitions.*;
import static me.bechberger.ebpf.runtime.TtyDefinitions.*;
import static me.bechberger.ebpf.runtime.TtyportDefinitions.*;
import static me.bechberger.ebpf.runtime.TunDefinitions.*;
import static me.bechberger.ebpf.runtime.Twl4030Definitions.*;
import static me.bechberger.ebpf.runtime.Twl6040Definitions.*;
import static me.bechberger.ebpf.runtime.TwlDefinitions.*;
import static me.bechberger.ebpf.runtime.TxDefinitions.*;
import static me.bechberger.ebpf.runtime.TypeDefinitions.*;
import static me.bechberger.ebpf.runtime.UDefinitions.*;
import static me.bechberger.ebpf.runtime.UartDefinitions.*;
import static me.bechberger.ebpf.runtime.UbsanDefinitions.*;
import static me.bechberger.ebpf.runtime.Udp4Definitions.*;
import static me.bechberger.ebpf.runtime.Udp6Definitions.*;
import static me.bechberger.ebpf.runtime.UdpDefinitions.*;
import static me.bechberger.ebpf.runtime.Udpv6Definitions.*;
import static me.bechberger.ebpf.runtime.UhciDefinitions.*;
import static me.bechberger.ebpf.runtime.UinputDefinitions.*;
import static me.bechberger.ebpf.runtime.UncoreDefinitions.*;
import static me.bechberger.ebpf.runtime.Univ8250Definitions.*;
import static me.bechberger.ebpf.runtime.UnixDefinitions.*;
import static me.bechberger.ebpf.runtime.UnlockDefinitions.*;
import static me.bechberger.ebpf.runtime.UnmapDefinitions.*;
import static me.bechberger.ebpf.runtime.UnregisterDefinitions.*;
import static me.bechberger.ebpf.runtime.UpdateDefinitions.*;
import static me.bechberger.ebpf.runtime.UprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.UsbDefinitions.*;
import static me.bechberger.ebpf.runtime.UsbdevfsDefinitions.*;
import static me.bechberger.ebpf.runtime.UserDefinitions.*;
import static me.bechberger.ebpf.runtime.UserfaultfdDefinitions.*;
import static me.bechberger.ebpf.runtime.Utf8Definitions.*;
import static me.bechberger.ebpf.runtime.UvDefinitions.*;
import static me.bechberger.ebpf.runtime.UvhDefinitions.*;
import static me.bechberger.ebpf.runtime.ValidateDefinitions.*;
import static me.bechberger.ebpf.runtime.VcDefinitions.*;
import static me.bechberger.ebpf.runtime.VcapDefinitions.*;
import static me.bechberger.ebpf.runtime.VcpuDefinitions.*;
import static me.bechberger.ebpf.runtime.VcsDefinitions.*;
import static me.bechberger.ebpf.runtime.VdsoDefinitions.*;
import static me.bechberger.ebpf.runtime.VerifyDefinitions.*;
import static me.bechberger.ebpf.runtime.VfatDefinitions.*;
import static me.bechberger.ebpf.runtime.VfsDefinitions.*;
import static me.bechberger.ebpf.runtime.VgaDefinitions.*;
import static me.bechberger.ebpf.runtime.VgaconDefinitions.*;
import static me.bechberger.ebpf.runtime.ViaDefinitions.*;
import static me.bechberger.ebpf.runtime.ViommuDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtblkDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtioDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtnetDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtscsiDefinitions.*;
import static me.bechberger.ebpf.runtime.VlanDefinitions.*;
import static me.bechberger.ebpf.runtime.VliDefinitions.*;
import static me.bechberger.ebpf.runtime.VmDefinitions.*;
import static me.bechberger.ebpf.runtime.VmaDefinitions.*;
import static me.bechberger.ebpf.runtime.VmallocDefinitions.*;
import static me.bechberger.ebpf.runtime.VmapDefinitions.*;
import static me.bechberger.ebpf.runtime.VmeDefinitions.*;
import static me.bechberger.ebpf.runtime.VmemmapDefinitions.*;
import static me.bechberger.ebpf.runtime.VmpressureDefinitions.*;
import static me.bechberger.ebpf.runtime.VmstatDefinitions.*;
import static me.bechberger.ebpf.runtime.VmwareDefinitions.*;
import static me.bechberger.ebpf.runtime.VpDefinitions.*;
import static me.bechberger.ebpf.runtime.VringDefinitions.*;
import static me.bechberger.ebpf.runtime.VtDefinitions.*;
import static me.bechberger.ebpf.runtime.WaitDefinitions.*;
import static me.bechberger.ebpf.runtime.WakeDefinitions.*;
import static me.bechberger.ebpf.runtime.WakeupDefinitions.*;
import static me.bechberger.ebpf.runtime.WalkDefinitions.*;
import static me.bechberger.ebpf.runtime.WarnDefinitions.*;
import static me.bechberger.ebpf.runtime.WatchDefinitions.*;
import static me.bechberger.ebpf.runtime.WatchdogDefinitions.*;
import static me.bechberger.ebpf.runtime.WbDefinitions.*;
import static me.bechberger.ebpf.runtime.WbtDefinitions.*;
import static me.bechberger.ebpf.runtime.WiphyDefinitions.*;
import static me.bechberger.ebpf.runtime.WirelessDefinitions.*;
import static me.bechberger.ebpf.runtime.Wm831xDefinitions.*;
import static me.bechberger.ebpf.runtime.Wm8350Definitions.*;
import static me.bechberger.ebpf.runtime.WorkqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.WpDefinitions.*;
import static me.bechberger.ebpf.runtime.WqDefinitions.*;
import static me.bechberger.ebpf.runtime.WriteDefinitions.*;
import static me.bechberger.ebpf.runtime.WritebackDefinitions.*;
import static me.bechberger.ebpf.runtime.WwDefinitions.*;
import static me.bechberger.ebpf.runtime.X2apicDefinitions.*;
import static me.bechberger.ebpf.runtime.X509Definitions.*;
import static me.bechberger.ebpf.runtime.X64Definitions.*;
import static me.bechberger.ebpf.runtime.X86Definitions.*;
import static me.bechberger.ebpf.runtime.XaDefinitions.*;
import static me.bechberger.ebpf.runtime.XasDefinitions.*;
import static me.bechberger.ebpf.runtime.XattrDefinitions.*;
import static me.bechberger.ebpf.runtime.XbcDefinitions.*;
import static me.bechberger.ebpf.runtime.XdbcDefinitions.*;
import static me.bechberger.ebpf.runtime.XdpDefinitions.*;
import static me.bechberger.ebpf.runtime.XenDefinitions.*;
import static me.bechberger.ebpf.runtime.XenbusDefinitions.*;
import static me.bechberger.ebpf.runtime.XennetDefinitions.*;
import static me.bechberger.ebpf.runtime.XenpfDefinitions.*;
import static me.bechberger.ebpf.runtime.Xfrm4Definitions.*;
import static me.bechberger.ebpf.runtime.Xfrm6Definitions.*;
import static me.bechberger.ebpf.runtime.XfrmDefinitions.*;
import static me.bechberger.ebpf.runtime.XhciDefinitions.*;
import static me.bechberger.ebpf.runtime.XpDefinitions.*;
import static me.bechberger.ebpf.runtime.XsDefinitions.*;
import static me.bechberger.ebpf.runtime.XskDefinitions.*;
import static me.bechberger.ebpf.runtime.XtsDefinitions.*;
import static me.bechberger.ebpf.runtime.XzDefinitions.*;
import static me.bechberger.ebpf.runtime.ZapDefinitions.*;
import static me.bechberger.ebpf.runtime.ZlibDefinitions.*;
import static me.bechberger.ebpf.runtime.ZoneDefinitions.*;
import static me.bechberger.ebpf.runtime.ZpoolDefinitions.*;
import static me.bechberger.ebpf.runtime.ZsDefinitions.*;
import static me.bechberger.ebpf.runtime.ZstdDefinitions.*;
import static me.bechberger.ebpf.runtime.ZswapDefinitions.*;
import static me.bechberger.ebpf.runtime.misc.*;
import static me.bechberger.ebpf.runtime.runtime.*;

/**
 * Generated class for BPF runtime types that start with skb
 */
@java.lang.SuppressWarnings("unused")
public final class SkbDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __skb_array_destroy_skb(Ptr<?> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("__sum16") short __skb_checksum_complete(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("__sum16") short __skb_checksum_complete_head(
      Ptr<sk_buff> skb, int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __skb_complete_tx_timestamp(Ptr<sk_buff> skb, Ptr<sock> sk, int tstype,
      boolean opt_stats) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__skb_datagram_iter((const struct sk_buff *)$arg1, $arg2, $arg3, $arg4, $arg5, (long unsigned int (*)(const void*, long unsigned int, void*, struct iov_iter*))$arg6, $arg7)")
  public static int __skb_datagram_iter(Ptr<sk_buff> skb, int offset, Ptr<iov_iter> to, int len,
      boolean fault_short, Ptr<?> cb, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<skb_ext> __skb_ext_alloc(@Unsigned @OriginalName("gfp_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __skb_ext_del(Ptr<sk_buff> skb, skb_ext_id id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __skb_ext_put(Ptr<skb_ext> ext) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> __skb_ext_set(Ptr<sk_buff> skb, skb_ext_id id, Ptr<skb_ext> ext) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__skb_flow_bpf_to_target((const struct bpf_flow_keys *)$arg1, $arg2, $arg3)")
  public static void __skb_flow_bpf_to_target(Ptr<bpf_flow_keys> flow_keys,
      Ptr<flow_dissector> flow_dissector, Ptr<?> target_container) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__skb_flow_dissect((const struct net *)$arg1, (const struct sk_buff *)$arg2, $arg3, $arg4, (const void *)$arg5, $arg6, $arg7, $arg8, $arg9)")
  public static boolean __skb_flow_dissect(Ptr<net> net, Ptr<sk_buff> skb,
      Ptr<flow_dissector> flow_dissector, Ptr<?> target_container, Ptr<?> data,
      @Unsigned @OriginalName("__be16") short proto, int nhoff, int hlen, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__skb_flow_dissect_arp((const struct sk_buff *)$arg1, $arg2, $arg3, (const void *)$arg4, $arg5, $arg6)")
  public static flow_dissect_ret __skb_flow_dissect_arp(Ptr<sk_buff> skb,
      Ptr<flow_dissector> flow_dissector, Ptr<?> target_container, Ptr<?> data, int nhoff,
      int hlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__skb_flow_dissect_gre((const struct sk_buff *)$arg1, $arg2, $arg3, $arg4, (const void *)$arg5, $arg6, $arg7, $arg8, $arg9)")
  public static flow_dissect_ret __skb_flow_dissect_gre(Ptr<sk_buff> skb,
      Ptr<flow_dissector_key_control> key_control, Ptr<flow_dissector> flow_dissector,
      Ptr<?> target_container, Ptr<?> data,
      Ptr<java.lang. @Unsigned @OriginalName("__be16") Short> p_proto,
      Ptr<java.lang.Integer> p_nhoff, Ptr<java.lang.Integer> p_hlen, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__skb_get_hash_net((const struct net *)$arg1, $arg2)")
  public static void __skb_get_hash_net(Ptr<net> net, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__skb_get_hash_symmetric_net((const struct net *)$arg1, (const struct sk_buff *)$arg2)")
  public static @Unsigned int __skb_get_hash_symmetric_net(Ptr<net> net, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__skb_get_poff((const struct sk_buff *)$arg1, (const void *)$arg2, (const struct flow_keys_basic *)$arg3, $arg4)")
  public static @Unsigned int __skb_get_poff(Ptr<sk_buff> skb, Ptr<?> data,
      Ptr<flow_keys_basic> keys, int hlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("__sum16") short __skb_gro_checksum_complete(
      Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sk_buff> __skb_gso_segment(Ptr<sk_buff> skb,
      @Unsigned @OriginalName("netdev_features_t") long features, boolean tx_path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __skb_pad(Ptr<sk_buff> skb, int pad, boolean free_on_error) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sk_buff> __skb_recv_datagram(Ptr<sock> sk, Ptr<sk_buff_head> sk_queue,
      @Unsigned int flags, Ptr<java.lang.Integer> off, Ptr<java.lang.Integer> err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sk_buff> __skb_recv_udp(Ptr<sock> sk, @Unsigned int flags,
      Ptr<java.lang.Integer> off, Ptr<java.lang.Integer> err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __skb_send_sock(Ptr<sock> sk, Ptr<sk_buff> skb, int offset, int len,
      @OriginalName("sendmsg_func") Ptr<?> sendmsg, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __skb_to_sgvec(Ptr<sk_buff> skb, Ptr<scatterlist> sg, int offset, int len,
      @Unsigned int recursion_level) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sk_buff> __skb_try_recv_datagram(Ptr<sock> sk, Ptr<sk_buff_head> queue,
      @Unsigned int flags, Ptr<java.lang.Integer> off, Ptr<java.lang.Integer> err,
      Ptr<Ptr<sk_buff>> last) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sk_buff> __skb_try_recv_from_queue(Ptr<sk_buff_head> queue, @Unsigned int flags,
      Ptr<java.lang.Integer> off, Ptr<java.lang.Integer> err, Ptr<Ptr<sk_buff>> last) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__skb_tstamp_tx($arg1, (const struct sk_buff *)$arg2, $arg3, $arg4, $arg5)")
  public static void __skb_tstamp_tx(Ptr<sk_buff> orig_skb, Ptr<sk_buff> ack_skb,
      Ptr<skb_shared_hwtstamps> hwtstamps, Ptr<sock> sk, int tstype) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__skb_udp_tunnel_segment($arg1, $arg2, (struct sk_buff* (*)(struct sk_buff*, long long unsigned int))$arg3, $arg4, $arg5)")
  public static Ptr<sk_buff> __skb_udp_tunnel_segment(Ptr<sk_buff> skb,
      @Unsigned @OriginalName("netdev_features_t") long features, Ptr<?> gso_inner_segment,
      @Unsigned @OriginalName("__be16") short new_protocol, boolean is_ipv6) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __skb_unclone_keeptruesize(Ptr<sk_buff> skb,
      @Unsigned @OriginalName("gfp_t") int pri) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __skb_vlan_pop(Ptr<sk_buff> skb, Ptr<java.lang. @Unsigned Short> vlan_tci) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__skb_wait_for_more_packets($arg1, $arg2, $arg3, $arg4, (const struct sk_buff *)$arg5)")
  public static int __skb_wait_for_more_packets(Ptr<sock> sk, Ptr<sk_buff_head> queue,
      Ptr<java.lang.Integer> err, Ptr<java.lang.Long> timeo_p, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__skb_warn_lro_forwarding((const struct sk_buff *)$arg1)")
  public static void __skb_warn_lro_forwarding(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __skb_zcopy_downgrade_managed(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void skb_abort_seq_read(Ptr<skb_seq_state> st) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void skb_add_rx_frag_netmem(Ptr<sk_buff> skb, int i,
      @Unsigned @OriginalName("netmem_ref") long netmem, int off, int size,
      @Unsigned int truesize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void skb_append(Ptr<sk_buff> old, Ptr<sk_buff> newsk, Ptr<sk_buff_head> list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int skb_append_pagefrags(Ptr<sk_buff> skb, Ptr<page> page, int offset,
      @Unsigned long size, @Unsigned long max_frags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void skb_attempt_defer_free(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("skb_checksum((const struct sk_buff *)$arg1, $arg2, $arg3, $arg4)")
  public static @Unsigned @OriginalName("__wsum") int skb_checksum(Ptr<sk_buff> skb, int offset,
      int len, @Unsigned @OriginalName("__wsum") int csum) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int skb_checksum_help(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int skb_checksum_setup(Ptr<sk_buff> skb, boolean recalculate) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<java.lang. @Unsigned @OriginalName("__sum16") Short> skb_checksum_setup_ip(
      Ptr<sk_buff> skb, int proto, @Unsigned int off) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int skb_checksum_setup_ipv6(Ptr<sk_buff> skb, boolean recalculate) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("skb_checksum_trimmed($arg1, $arg2, (short unsigned int (*)(struct sk_buff*))$arg3)")
  public static Ptr<sk_buff> skb_checksum_trimmed(Ptr<sk_buff> skb, @Unsigned int transport_len,
      Ptr<?> skb_chkf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sk_buff> skb_clone(Ptr<sk_buff> skb,
      @Unsigned @OriginalName("gfp_t") int gfp_mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void skb_clone_fraglist(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sk_buff> skb_clone_sk(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void skb_clone_tx_timestamp(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void skb_coalesce_rx_frag(Ptr<sk_buff> skb, int i, int size,
      @Unsigned int truesize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void skb_complete_tx_timestamp(Ptr<sk_buff> skb,
      Ptr<skb_shared_hwtstamps> hwtstamps) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void skb_complete_wifi_ack(Ptr<sk_buff> skb, boolean acked) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void skb_condense(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void skb_consume_udp(Ptr<sock> sk, Ptr<sk_buff> skb, int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("skb_copy((const struct sk_buff *)$arg1, $arg2)")
  public static Ptr<sk_buff> skb_copy(Ptr<sk_buff> skb,
      @Unsigned @OriginalName("gfp_t") int gfp_mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("skb_copy_and_crc32c_datagram_iter((const struct sk_buff *)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int skb_copy_and_crc32c_datagram_iter(Ptr<sk_buff> skb, int offset,
      Ptr<iov_iter> to, int len, Ptr<java.lang. @Unsigned Integer> crcp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("skb_copy_and_csum_bits((const struct sk_buff *)$arg1, $arg2, $arg3, $arg4)")
  public static @Unsigned @OriginalName("__wsum") int skb_copy_and_csum_bits(Ptr<sk_buff> skb,
      int offset, Ptr<java.lang.Character> to, int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int skb_copy_and_csum_datagram_msg(Ptr<sk_buff> skb, int hlen, Ptr<msghdr> msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("skb_copy_and_csum_dev((const struct sk_buff *)$arg1, $arg2)")
  public static void skb_copy_and_csum_dev(Ptr<sk_buff> skb, Ptr<java.lang.Character> to) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("skb_copy_bits((const struct sk_buff *)$arg1, $arg2, $arg3, $arg4)")
  public static int skb_copy_bits(Ptr<sk_buff> skb, int offset, Ptr<?> to, int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int skb_copy_datagram_from_iter(Ptr<sk_buff> skb, int offset, Ptr<iov_iter> from,
      int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int skb_copy_datagram_from_iter_full(Ptr<sk_buff> skb, int offset,
      Ptr<iov_iter> from, int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("skb_copy_datagram_iter((const struct sk_buff *)$arg1, $arg2, $arg3, $arg4)")
  public static int skb_copy_datagram_iter(Ptr<sk_buff> skb, int offset, Ptr<iov_iter> to,
      int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("skb_copy_expand((const struct sk_buff *)$arg1, $arg2, $arg3, $arg4)")
  public static Ptr<sk_buff> skb_copy_expand(Ptr<sk_buff> skb, int newheadroom, int newtailroom,
      @Unsigned @OriginalName("gfp_t") int gfp_mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("skb_copy_header($arg1, (const struct sk_buff *)$arg2)")
  public static void skb_copy_header(Ptr<sk_buff> _new, Ptr<sk_buff> old) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int skb_copy_seq_read(Ptr<skb_seq_state> st, int offset, Ptr<?> to, int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("skb_copy_to_linear_data($arg1, (const void *)$arg2, (const unsigned int)$arg3)")
  public static void skb_copy_to_linear_data(Ptr<sk_buff> skb, Ptr<?> from, @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int skb_copy_ubufs(Ptr<sk_buff> skb,
      @Unsigned @OriginalName("gfp_t") int gfp_mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int skb_cow_data(Ptr<sk_buff> skb, int tailbits, Ptr<Ptr<sk_buff>> trailer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("skb_cow_data_for_xdp($arg1, $arg2, (const struct bpf_prog *)$arg3)")
  public static int skb_cow_data_for_xdp(Ptr<page_pool> pool, Ptr<Ptr<sk_buff>> pskb,
      Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("skb_crc32c((const struct sk_buff *)$arg1, $arg2, $arg3, $arg4)")
  public static @Unsigned int skb_crc32c(Ptr<sk_buff> skb, int offset, int len, @Unsigned int crc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int skb_crc32c_csum_help(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("skb_csum_hwoffload_help($arg1, (const long long unsigned int)$arg2)")
  public static int skb_csum_hwoffload_help(Ptr<sk_buff> skb,
      @Unsigned @OriginalName("netdev_features_t") long features) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean skb_defer_rx_timestamp(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sk_buff> skb_dequeue(Ptr<sk_buff_head> list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sk_buff> skb_dequeue_tail(Ptr<sk_buff_head> list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int skb_do_copy_data_nocache(Ptr<sock> sk, Ptr<sk_buff> skb, Ptr<iov_iter> from,
      String to, int copy, int offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int skb_do_redirect(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dst_entry> skb_dst_pop(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("skb_dump((const u8 *)$arg1, (const struct sk_buff *)$arg2, $arg3)")
  public static void skb_dump(String level, Ptr<sk_buff> skb, boolean full_pkt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int skb_ensure_writable(Ptr<sk_buff> skb, @Unsigned int write_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int skb_ensure_writable_head_tail(Ptr<sk_buff> skb, Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void skb_errqueue_purge(Ptr<sk_buff_head> list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sk_buff> skb_eth_gso_segment(Ptr<sk_buff> skb,
      @Unsigned @OriginalName("netdev_features_t") long features,
      @Unsigned @OriginalName("__be16") short type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int skb_eth_pop(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("skb_eth_push($arg1, (const u8 *)$arg2, (const u8 *)$arg3)")
  public static int skb_eth_push(Ptr<sk_buff> skb, String dst, String src) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sk_buff> skb_expand_head(Ptr<sk_buff> skb, @Unsigned int headroom) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> skb_ext_add(Ptr<sk_buff> skb, skb_ext_id id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void skb_ext_del(Ptr<sk_buff> skb, skb_ext_id id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<skb_ext> skb_ext_maybe_cow(Ptr<skb_ext> old, @Unsigned int old_active) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int skb_find_text(Ptr<sk_buff> skb, @Unsigned int from, @Unsigned int to,
      Ptr<ts_config> config) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("skb_flow_dissect_ct((const struct sk_buff *)$arg1, $arg2, $arg3, $arg4, $arg5, $arg6, $arg7)")
  public static void skb_flow_dissect_ct(Ptr<sk_buff> skb, Ptr<flow_dissector> flow_dissector,
      Ptr<?> target_container, Ptr<java.lang. @Unsigned Short> ctinfo_map, @Unsigned long mapsize,
      boolean post_ct, @Unsigned short zone) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("skb_flow_dissect_hash((const struct sk_buff *)$arg1, $arg2, $arg3)")
  public static void skb_flow_dissect_hash(Ptr<sk_buff> skb, Ptr<flow_dissector> flow_dissector,
      Ptr<?> target_container) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("skb_flow_dissect_meta((const struct sk_buff *)$arg1, $arg2, $arg3)")
  public static void skb_flow_dissect_meta(Ptr<sk_buff> skb, Ptr<flow_dissector> flow_dissector,
      Ptr<?> target_container) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("skb_flow_dissect_tunnel_info((const struct sk_buff *)$arg1, $arg2, $arg3)")
  public static void skb_flow_dissect_tunnel_info(Ptr<sk_buff> skb,
      Ptr<flow_dissector> flow_dissector, Ptr<?> target_container) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("skb_flow_dissector_init($arg1, (const struct flow_dissector_key *)$arg2, $arg3)")
  public static void skb_flow_dissector_init(Ptr<flow_dissector> flow_dissector,
      Ptr<flow_dissector_key> key, @Unsigned int key_count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("skb_flow_get_icmp_tci((const struct sk_buff *)$arg1, $arg2, (const void *)$arg3, $arg4, $arg5)")
  public static void skb_flow_get_icmp_tci(Ptr<sk_buff> skb, Ptr<flow_dissector_key_icmp> key_icmp,
      Ptr<?> data, int thoff, int hlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("skb_flow_get_ports((const struct sk_buff *)$arg1, $arg2, $arg3, (const void *)$arg4, $arg5)")
  public static @Unsigned @OriginalName("__be32") int skb_flow_get_ports(Ptr<sk_buff> skb,
      int thoff, char ip_proto, Ptr<?> data, int hlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void skb_free_datagram(Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void skb_free_head(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("skb_get_hash_perturb((const struct sk_buff *)$arg1, (const struct {\n"
          + "  long long unsigned int key[2];\n"
          + "} *)$arg2)")
  public static @Unsigned int skb_get_hash_perturb(Ptr<sk_buff> skb, Ptr<siphash_key_t> perturb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("skb_get_poff((const struct sk_buff *)$arg1)")
  public static @Unsigned int skb_get_poff(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int skb_get_tx_timestamp(Ptr<sk_buff> skb, Ptr<sock> sk, Ptr<timespec64> ts) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int skb_gro_receive(Ptr<sk_buff> p, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int skb_gro_receive_list(Ptr<sk_buff> p, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("skb_gso_transport_seglen((const struct sk_buff *)$arg1)")
  public static @Unsigned int skb_gso_transport_seglen(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("skb_gso_validate_mac_len((const struct sk_buff *)$arg1, $arg2)")
  public static boolean skb_gso_validate_mac_len(Ptr<sk_buff> skb, @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("skb_gso_validate_network_len((const struct sk_buff *)$arg1, $arg2)")
  public static boolean skb_gso_validate_network_len(Ptr<sk_buff> skb, @Unsigned int mtu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("skb_has_tx_timestamp($arg1, (const struct sock *)$arg2)")
  public static boolean skb_has_tx_timestamp(Ptr<sk_buff> skb, Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void skb_headers_offset_update(Ptr<sk_buff> skb, int off) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void skb_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int skb_kill_datagram(Ptr<sock> sk, Ptr<sk_buff> skb, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sk_buff> skb_mac_gso_segment(Ptr<sk_buff> skb,
      @Unsigned @OriginalName("netdev_features_t") long features) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("skb_metadata_dst_cmp((const struct sk_buff *)$arg1, (const struct sk_buff *)$arg2)")
  public static int skb_metadata_dst_cmp(Ptr<sk_buff> skb_a, Ptr<sk_buff> skb_b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sk_buff> skb_morph(Ptr<sk_buff> dst, Ptr<sk_buff> src) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int skb_mpls_dec_ttl(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int skb_mpls_pop(Ptr<sk_buff> skb,
      @Unsigned @OriginalName("__be16") short next_proto, int mac_len, boolean ethernet) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int skb_mpls_push(Ptr<sk_buff> skb, @Unsigned @OriginalName("__be32") int mpls_lse,
      @Unsigned @OriginalName("__be16") short mpls_proto, int mac_len, boolean ethernet) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int skb_mpls_update_lse(Ptr<sk_buff> skb,
      @Unsigned @OriginalName("__be32") int mpls_lse) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("__be16") short skb_network_protocol(Ptr<sk_buff> skb,
      Ptr<java.lang.Integer> depth) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void skb_orphan_partial(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean skb_page_frag_refill(@Unsigned int sz, Ptr<page_frag> pfrag,
      @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("skb_panic($arg1, $arg2, $arg3, (const u8 *)$arg4)")
  public static void skb_panic(Ptr<sk_buff> skb, @Unsigned int sz, Ptr<?> addr, String msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean skb_partial_csum_set(Ptr<sk_buff> skb, @Unsigned short start,
      @Unsigned short off) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int skb_pp_cow_data(Ptr<page_pool> pool, Ptr<Ptr<sk_buff>> pskb,
      @Unsigned int headroom) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void skb_prepare_seq_read(Ptr<sk_buff> skb, @Unsigned int from, @Unsigned int to,
      Ptr<skb_seq_state> st) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> skb_pull(Ptr<sk_buff> skb, @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> skb_pull_data(Ptr<sk_buff> skb, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> skb_pull_rcsum(Ptr<sk_buff> skb, @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> skb_push(Ptr<sk_buff> skb, @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> skb_put(Ptr<sk_buff> skb, @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("skb_put_data($arg1, (const void *)$arg2, $arg3)")
  public static Ptr<?> skb_put_data(Ptr<sk_buff> skb, Ptr<?> data, @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void skb_queue_head(Ptr<sk_buff_head> list, Ptr<sk_buff> newsk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void skb_queue_purge_reason(Ptr<sk_buff_head> list, skb_drop_reason reason) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void skb_queue_tail(Ptr<sk_buff_head> list, Ptr<sk_buff> newsk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int skb_rbtree_purge(Ptr<rb_root> root) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sk_buff> skb_realloc_headroom(Ptr<sk_buff> skb, @Unsigned int headroom) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sk_buff> skb_recv_datagram(Ptr<sock> sk, @Unsigned int flags,
      Ptr<java.lang.Integer> err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void skb_recv_done(Ptr<virtqueue> rvq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void skb_release_data(Ptr<sk_buff> skb, skb_drop_reason reason) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void skb_release_head_state(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sk_buff> skb_reorder_vlan_header(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void skb_scrub_packet(Ptr<sk_buff> skb, boolean xnet) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sk_buff> skb_segment(Ptr<sk_buff> head_skb,
      @Unsigned @OriginalName("netdev_features_t") long features) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sk_buff> skb_segment_list(Ptr<sk_buff> skb,
      @Unsigned @OriginalName("netdev_features_t") long features, @Unsigned int offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int skb_send_sock(Ptr<sock> sk, Ptr<sk_buff> skb, int offset, int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int skb_send_sock_locked(Ptr<sock> sk, Ptr<sk_buff> skb, int offset, int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int skb_send_sock_locked_with_flags(Ptr<sock> sk, Ptr<sk_buff> skb, int offset,
      int len, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("skb_seq_read($arg1, (const u8**)$arg2, $arg3)")
  public static @Unsigned int skb_seq_read(@Unsigned int consumed,
      Ptr<Ptr<java.lang.Character>> data, Ptr<skb_seq_state> st) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void skb_set_owner_w(Ptr<sk_buff> skb, Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int skb_shift(Ptr<sk_buff> tgt, Ptr<sk_buff> skb, int shiftlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int skb_splice_bits(Ptr<sk_buff> skb, Ptr<sock> sk, @Unsigned int offset,
      Ptr<pipe_inode_info> pipe, @Unsigned int tlen, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long skb_splice_from_iter(Ptr<sk_buff> skb,
      Ptr<iov_iter> iter, @OriginalName("ssize_t") long maxsize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("skb_split($arg1, $arg2, (const unsigned int)$arg3)")
  public static void skb_split(Ptr<sk_buff> skb, Ptr<sk_buff> skb1, @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("skb_still_in_host_queue($arg1, (const struct sk_buff *)$arg2)")
  public static boolean skb_still_in_host_queue(Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("skb_store_bits($arg1, $arg2, (const void *)$arg3, $arg4)")
  public static int skb_store_bits(Ptr<sk_buff> skb, int offset, Ptr<?> from, int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int skb_to_sgvec(Ptr<sk_buff> skb, Ptr<scatterlist> sg, int offset, int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int skb_to_sgvec_nomark(Ptr<sk_buff> skb, Ptr<scatterlist> sg, int offset,
      int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void skb_trim(Ptr<sk_buff> skb, @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean skb_try_coalesce(Ptr<sk_buff> to, Ptr<sk_buff> from,
      Ptr<java.lang. @OriginalName("bool") Boolean> fragstolen,
      Ptr<java.lang.Integer> delta_truesize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void skb_ts_finish(Ptr<ts_config> conf, Ptr<ts_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("skb_ts_get_next_block($arg1, (const u8**)$arg2, $arg3, $arg4)")
  public static @Unsigned int skb_ts_get_next_block(@Unsigned int offset,
      Ptr<Ptr<java.lang.Character>> text, Ptr<ts_config> conf, Ptr<ts_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void skb_tstamp_tx(Ptr<sk_buff> orig_skb, Ptr<skb_shared_hwtstamps> hwtstamps) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int skb_tunnel_check_pmtu(Ptr<sk_buff> skb, Ptr<dst_entry> encap_dst, int headroom,
      boolean reply) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void skb_tx_error(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sk_buff> skb_udp_tunnel_segment(Ptr<sk_buff> skb,
      @Unsigned @OriginalName("netdev_features_t") long features, boolean is_ipv6) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void skb_unlink(Ptr<sk_buff> skb, Ptr<sk_buff_head> list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int skb_vlan_pop(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int skb_vlan_push(Ptr<sk_buff> skb,
      @Unsigned @OriginalName("__be16") short vlan_proto, @Unsigned short vlan_tci) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sk_buff> skb_vlan_untag(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("skb_warn_bad_offload((const struct sk_buff *)$arg1)")
  public static void skb_warn_bad_offload(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void skb_xmit_done(Ptr<virtqueue> vq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int skb_zerocopy(Ptr<sk_buff> to, Ptr<sk_buff> from, int len, int hlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int skb_zerocopy_clone(Ptr<sk_buff> nskb, Ptr<sk_buff> orig,
      @Unsigned @OriginalName("gfp_t") int gfp_mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("skb_zerocopy_headlen((const struct sk_buff *)$arg1)")
  public static @Unsigned int skb_zerocopy_headlen(Ptr<sk_buff> from) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int skb_zerocopy_iter_stream(Ptr<sock> sk, Ptr<sk_buff> skb, Ptr<msghdr> msg,
      int len, Ptr<ubuf_info> uarg, Ptr<net_devmem_dmabuf_binding> binding) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct skb_ext"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class skb_ext extends Struct {
    public @OriginalName("refcount_t") refcount_struct refcnt;

    public char @Size(5) [] offset;

    public char chunks;

    public char @Size(0) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum skb_ext_id"
  )
  public enum skb_ext_id implements Enum<skb_ext_id>, TypedEnum<skb_ext_id, java.lang. @Unsigned Integer> {
    /**
     * {@code SKB_EXT_BRIDGE_NF = 0}
     */
    @EnumMember(
        value = 0L,
        name = "SKB_EXT_BRIDGE_NF"
    )
    SKB_EXT_BRIDGE_NF,

    /**
     * {@code SKB_EXT_SEC_PATH = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SKB_EXT_SEC_PATH"
    )
    SKB_EXT_SEC_PATH,

    /**
     * {@code TC_SKB_EXT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "TC_SKB_EXT"
    )
    TC_SKB_EXT,

    /**
     * {@code SKB_EXT_MPTCP = 3}
     */
    @EnumMember(
        value = 3L,
        name = "SKB_EXT_MPTCP"
    )
    SKB_EXT_MPTCP,

    /**
     * {@code SKB_EXT_MCTP = 4}
     */
    @EnumMember(
        value = 4L,
        name = "SKB_EXT_MCTP"
    )
    SKB_EXT_MCTP,

    /**
     * {@code SKB_EXT_NUM = 5}
     */
    @EnumMember(
        value = 5L,
        name = "SKB_EXT_NUM"
    )
    SKB_EXT_NUM
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct skb_shared_hwtstamps"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class skb_shared_hwtstamps extends Struct {
    @InlineUnion(3226)
    public @OriginalName("ktime_t") long hwtstamp;

    @InlineUnion(3226)
    public Ptr<?> netdev_data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum skb_drop_reason"
  )
  public enum skb_drop_reason implements Enum<skb_drop_reason>, TypedEnum<skb_drop_reason, java.lang. @Unsigned Integer> {
    /**
     * {@code SKB_NOT_DROPPED_YET = 0}
     */
    @EnumMember(
        value = 0L,
        name = "SKB_NOT_DROPPED_YET"
    )
    SKB_NOT_DROPPED_YET,

    /**
     * {@code SKB_CONSUMED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SKB_CONSUMED"
    )
    SKB_CONSUMED,

    /**
     * {@code SKB_DROP_REASON_NOT_SPECIFIED = 2}
     */
    @EnumMember(
        value = 2L,
        name = "SKB_DROP_REASON_NOT_SPECIFIED"
    )
    SKB_DROP_REASON_NOT_SPECIFIED,

    /**
     * {@code SKB_DROP_REASON_NO_SOCKET = 3}
     */
    @EnumMember(
        value = 3L,
        name = "SKB_DROP_REASON_NO_SOCKET"
    )
    SKB_DROP_REASON_NO_SOCKET,

    /**
     * {@code SKB_DROP_REASON_SOCKET_CLOSE = 4}
     */
    @EnumMember(
        value = 4L,
        name = "SKB_DROP_REASON_SOCKET_CLOSE"
    )
    SKB_DROP_REASON_SOCKET_CLOSE,

    /**
     * {@code SKB_DROP_REASON_SOCKET_FILTER = 5}
     */
    @EnumMember(
        value = 5L,
        name = "SKB_DROP_REASON_SOCKET_FILTER"
    )
    SKB_DROP_REASON_SOCKET_FILTER,

    /**
     * {@code SKB_DROP_REASON_SOCKET_RCVBUFF = 6}
     */
    @EnumMember(
        value = 6L,
        name = "SKB_DROP_REASON_SOCKET_RCVBUFF"
    )
    SKB_DROP_REASON_SOCKET_RCVBUFF,

    /**
     * {@code SKB_DROP_REASON_UNIX_DISCONNECT = 7}
     */
    @EnumMember(
        value = 7L,
        name = "SKB_DROP_REASON_UNIX_DISCONNECT"
    )
    SKB_DROP_REASON_UNIX_DISCONNECT,

    /**
     * {@code SKB_DROP_REASON_UNIX_SKIP_OOB = 8}
     */
    @EnumMember(
        value = 8L,
        name = "SKB_DROP_REASON_UNIX_SKIP_OOB"
    )
    SKB_DROP_REASON_UNIX_SKIP_OOB,

    /**
     * {@code SKB_DROP_REASON_PKT_TOO_SMALL = 9}
     */
    @EnumMember(
        value = 9L,
        name = "SKB_DROP_REASON_PKT_TOO_SMALL"
    )
    SKB_DROP_REASON_PKT_TOO_SMALL,

    /**
     * {@code SKB_DROP_REASON_TCP_CSUM = 10}
     */
    @EnumMember(
        value = 10L,
        name = "SKB_DROP_REASON_TCP_CSUM"
    )
    SKB_DROP_REASON_TCP_CSUM,

    /**
     * {@code SKB_DROP_REASON_UDP_CSUM = 11}
     */
    @EnumMember(
        value = 11L,
        name = "SKB_DROP_REASON_UDP_CSUM"
    )
    SKB_DROP_REASON_UDP_CSUM,

    /**
     * {@code SKB_DROP_REASON_NETFILTER_DROP = 12}
     */
    @EnumMember(
        value = 12L,
        name = "SKB_DROP_REASON_NETFILTER_DROP"
    )
    SKB_DROP_REASON_NETFILTER_DROP,

    /**
     * {@code SKB_DROP_REASON_OTHERHOST = 13}
     */
    @EnumMember(
        value = 13L,
        name = "SKB_DROP_REASON_OTHERHOST"
    )
    SKB_DROP_REASON_OTHERHOST,

    /**
     * {@code SKB_DROP_REASON_IP_CSUM = 14}
     */
    @EnumMember(
        value = 14L,
        name = "SKB_DROP_REASON_IP_CSUM"
    )
    SKB_DROP_REASON_IP_CSUM,

    /**
     * {@code SKB_DROP_REASON_IP_INHDR = 15}
     */
    @EnumMember(
        value = 15L,
        name = "SKB_DROP_REASON_IP_INHDR"
    )
    SKB_DROP_REASON_IP_INHDR,

    /**
     * {@code SKB_DROP_REASON_IP_RPFILTER = 16}
     */
    @EnumMember(
        value = 16L,
        name = "SKB_DROP_REASON_IP_RPFILTER"
    )
    SKB_DROP_REASON_IP_RPFILTER,

    /**
     * {@code SKB_DROP_REASON_UNICAST_IN_L2_MULTICAST = 17}
     */
    @EnumMember(
        value = 17L,
        name = "SKB_DROP_REASON_UNICAST_IN_L2_MULTICAST"
    )
    SKB_DROP_REASON_UNICAST_IN_L2_MULTICAST,

    /**
     * {@code SKB_DROP_REASON_XFRM_POLICY = 18}
     */
    @EnumMember(
        value = 18L,
        name = "SKB_DROP_REASON_XFRM_POLICY"
    )
    SKB_DROP_REASON_XFRM_POLICY,

    /**
     * {@code SKB_DROP_REASON_IP_NOPROTO = 19}
     */
    @EnumMember(
        value = 19L,
        name = "SKB_DROP_REASON_IP_NOPROTO"
    )
    SKB_DROP_REASON_IP_NOPROTO,

    /**
     * {@code SKB_DROP_REASON_PROTO_MEM = 20}
     */
    @EnumMember(
        value = 20L,
        name = "SKB_DROP_REASON_PROTO_MEM"
    )
    SKB_DROP_REASON_PROTO_MEM,

    /**
     * {@code SKB_DROP_REASON_TCP_AUTH_HDR = 21}
     */
    @EnumMember(
        value = 21L,
        name = "SKB_DROP_REASON_TCP_AUTH_HDR"
    )
    SKB_DROP_REASON_TCP_AUTH_HDR,

    /**
     * {@code SKB_DROP_REASON_TCP_MD5NOTFOUND = 22}
     */
    @EnumMember(
        value = 22L,
        name = "SKB_DROP_REASON_TCP_MD5NOTFOUND"
    )
    SKB_DROP_REASON_TCP_MD5NOTFOUND,

    /**
     * {@code SKB_DROP_REASON_TCP_MD5UNEXPECTED = 23}
     */
    @EnumMember(
        value = 23L,
        name = "SKB_DROP_REASON_TCP_MD5UNEXPECTED"
    )
    SKB_DROP_REASON_TCP_MD5UNEXPECTED,

    /**
     * {@code SKB_DROP_REASON_TCP_MD5FAILURE = 24}
     */
    @EnumMember(
        value = 24L,
        name = "SKB_DROP_REASON_TCP_MD5FAILURE"
    )
    SKB_DROP_REASON_TCP_MD5FAILURE,

    /**
     * {@code SKB_DROP_REASON_TCP_AONOTFOUND = 25}
     */
    @EnumMember(
        value = 25L,
        name = "SKB_DROP_REASON_TCP_AONOTFOUND"
    )
    SKB_DROP_REASON_TCP_AONOTFOUND,

    /**
     * {@code SKB_DROP_REASON_TCP_AOUNEXPECTED = 26}
     */
    @EnumMember(
        value = 26L,
        name = "SKB_DROP_REASON_TCP_AOUNEXPECTED"
    )
    SKB_DROP_REASON_TCP_AOUNEXPECTED,

    /**
     * {@code SKB_DROP_REASON_TCP_AOKEYNOTFOUND = 27}
     */
    @EnumMember(
        value = 27L,
        name = "SKB_DROP_REASON_TCP_AOKEYNOTFOUND"
    )
    SKB_DROP_REASON_TCP_AOKEYNOTFOUND,

    /**
     * {@code SKB_DROP_REASON_TCP_AOFAILURE = 28}
     */
    @EnumMember(
        value = 28L,
        name = "SKB_DROP_REASON_TCP_AOFAILURE"
    )
    SKB_DROP_REASON_TCP_AOFAILURE,

    /**
     * {@code SKB_DROP_REASON_SOCKET_BACKLOG = 29}
     */
    @EnumMember(
        value = 29L,
        name = "SKB_DROP_REASON_SOCKET_BACKLOG"
    )
    SKB_DROP_REASON_SOCKET_BACKLOG,

    /**
     * {@code SKB_DROP_REASON_TCP_FLAGS = 30}
     */
    @EnumMember(
        value = 30L,
        name = "SKB_DROP_REASON_TCP_FLAGS"
    )
    SKB_DROP_REASON_TCP_FLAGS,

    /**
     * {@code SKB_DROP_REASON_TCP_ABORT_ON_DATA = 31}
     */
    @EnumMember(
        value = 31L,
        name = "SKB_DROP_REASON_TCP_ABORT_ON_DATA"
    )
    SKB_DROP_REASON_TCP_ABORT_ON_DATA,

    /**
     * {@code SKB_DROP_REASON_TCP_ZEROWINDOW = 32}
     */
    @EnumMember(
        value = 32L,
        name = "SKB_DROP_REASON_TCP_ZEROWINDOW"
    )
    SKB_DROP_REASON_TCP_ZEROWINDOW,

    /**
     * {@code SKB_DROP_REASON_TCP_OLD_DATA = 33}
     */
    @EnumMember(
        value = 33L,
        name = "SKB_DROP_REASON_TCP_OLD_DATA"
    )
    SKB_DROP_REASON_TCP_OLD_DATA,

    /**
     * {@code SKB_DROP_REASON_TCP_OVERWINDOW = 34}
     */
    @EnumMember(
        value = 34L,
        name = "SKB_DROP_REASON_TCP_OVERWINDOW"
    )
    SKB_DROP_REASON_TCP_OVERWINDOW,

    /**
     * {@code SKB_DROP_REASON_TCP_OFOMERGE = 35}
     */
    @EnumMember(
        value = 35L,
        name = "SKB_DROP_REASON_TCP_OFOMERGE"
    )
    SKB_DROP_REASON_TCP_OFOMERGE,

    /**
     * {@code SKB_DROP_REASON_TCP_RFC7323_PAWS = 36}
     */
    @EnumMember(
        value = 36L,
        name = "SKB_DROP_REASON_TCP_RFC7323_PAWS"
    )
    SKB_DROP_REASON_TCP_RFC7323_PAWS,

    /**
     * {@code SKB_DROP_REASON_TCP_RFC7323_PAWS_ACK = 37}
     */
    @EnumMember(
        value = 37L,
        name = "SKB_DROP_REASON_TCP_RFC7323_PAWS_ACK"
    )
    SKB_DROP_REASON_TCP_RFC7323_PAWS_ACK,

    /**
     * {@code SKB_DROP_REASON_TCP_RFC7323_TW_PAWS = 38}
     */
    @EnumMember(
        value = 38L,
        name = "SKB_DROP_REASON_TCP_RFC7323_TW_PAWS"
    )
    SKB_DROP_REASON_TCP_RFC7323_TW_PAWS,

    /**
     * {@code SKB_DROP_REASON_TCP_RFC7323_TSECR = 39}
     */
    @EnumMember(
        value = 39L,
        name = "SKB_DROP_REASON_TCP_RFC7323_TSECR"
    )
    SKB_DROP_REASON_TCP_RFC7323_TSECR,

    /**
     * {@code SKB_DROP_REASON_TCP_LISTEN_OVERFLOW = 40}
     */
    @EnumMember(
        value = 40L,
        name = "SKB_DROP_REASON_TCP_LISTEN_OVERFLOW"
    )
    SKB_DROP_REASON_TCP_LISTEN_OVERFLOW,

    /**
     * {@code SKB_DROP_REASON_TCP_OLD_SEQUENCE = 41}
     */
    @EnumMember(
        value = 41L,
        name = "SKB_DROP_REASON_TCP_OLD_SEQUENCE"
    )
    SKB_DROP_REASON_TCP_OLD_SEQUENCE,

    /**
     * {@code SKB_DROP_REASON_TCP_INVALID_SEQUENCE = 42}
     */
    @EnumMember(
        value = 42L,
        name = "SKB_DROP_REASON_TCP_INVALID_SEQUENCE"
    )
    SKB_DROP_REASON_TCP_INVALID_SEQUENCE,

    /**
     * {@code SKB_DROP_REASON_TCP_INVALID_END_SEQUENCE = 43}
     */
    @EnumMember(
        value = 43L,
        name = "SKB_DROP_REASON_TCP_INVALID_END_SEQUENCE"
    )
    SKB_DROP_REASON_TCP_INVALID_END_SEQUENCE,

    /**
     * {@code SKB_DROP_REASON_TCP_INVALID_ACK_SEQUENCE = 44}
     */
    @EnumMember(
        value = 44L,
        name = "SKB_DROP_REASON_TCP_INVALID_ACK_SEQUENCE"
    )
    SKB_DROP_REASON_TCP_INVALID_ACK_SEQUENCE,

    /**
     * {@code SKB_DROP_REASON_TCP_RESET = 45}
     */
    @EnumMember(
        value = 45L,
        name = "SKB_DROP_REASON_TCP_RESET"
    )
    SKB_DROP_REASON_TCP_RESET,

    /**
     * {@code SKB_DROP_REASON_TCP_INVALID_SYN = 46}
     */
    @EnumMember(
        value = 46L,
        name = "SKB_DROP_REASON_TCP_INVALID_SYN"
    )
    SKB_DROP_REASON_TCP_INVALID_SYN,

    /**
     * {@code SKB_DROP_REASON_TCP_CLOSE = 47}
     */
    @EnumMember(
        value = 47L,
        name = "SKB_DROP_REASON_TCP_CLOSE"
    )
    SKB_DROP_REASON_TCP_CLOSE,

    /**
     * {@code SKB_DROP_REASON_TCP_FASTOPEN = 48}
     */
    @EnumMember(
        value = 48L,
        name = "SKB_DROP_REASON_TCP_FASTOPEN"
    )
    SKB_DROP_REASON_TCP_FASTOPEN,

    /**
     * {@code SKB_DROP_REASON_TCP_OLD_ACK = 49}
     */
    @EnumMember(
        value = 49L,
        name = "SKB_DROP_REASON_TCP_OLD_ACK"
    )
    SKB_DROP_REASON_TCP_OLD_ACK,

    /**
     * {@code SKB_DROP_REASON_TCP_TOO_OLD_ACK = 50}
     */
    @EnumMember(
        value = 50L,
        name = "SKB_DROP_REASON_TCP_TOO_OLD_ACK"
    )
    SKB_DROP_REASON_TCP_TOO_OLD_ACK,

    /**
     * {@code SKB_DROP_REASON_TCP_ACK_UNSENT_DATA = 51}
     */
    @EnumMember(
        value = 51L,
        name = "SKB_DROP_REASON_TCP_ACK_UNSENT_DATA"
    )
    SKB_DROP_REASON_TCP_ACK_UNSENT_DATA,

    /**
     * {@code SKB_DROP_REASON_TCP_OFO_QUEUE_PRUNE = 52}
     */
    @EnumMember(
        value = 52L,
        name = "SKB_DROP_REASON_TCP_OFO_QUEUE_PRUNE"
    )
    SKB_DROP_REASON_TCP_OFO_QUEUE_PRUNE,

    /**
     * {@code SKB_DROP_REASON_TCP_OFO_DROP = 53}
     */
    @EnumMember(
        value = 53L,
        name = "SKB_DROP_REASON_TCP_OFO_DROP"
    )
    SKB_DROP_REASON_TCP_OFO_DROP,

    /**
     * {@code SKB_DROP_REASON_IP_OUTNOROUTES = 54}
     */
    @EnumMember(
        value = 54L,
        name = "SKB_DROP_REASON_IP_OUTNOROUTES"
    )
    SKB_DROP_REASON_IP_OUTNOROUTES,

    /**
     * {@code SKB_DROP_REASON_BPF_CGROUP_EGRESS = 55}
     */
    @EnumMember(
        value = 55L,
        name = "SKB_DROP_REASON_BPF_CGROUP_EGRESS"
    )
    SKB_DROP_REASON_BPF_CGROUP_EGRESS,

    /**
     * {@code SKB_DROP_REASON_IPV6DISABLED = 56}
     */
    @EnumMember(
        value = 56L,
        name = "SKB_DROP_REASON_IPV6DISABLED"
    )
    SKB_DROP_REASON_IPV6DISABLED,

    /**
     * {@code SKB_DROP_REASON_NEIGH_CREATEFAIL = 57}
     */
    @EnumMember(
        value = 57L,
        name = "SKB_DROP_REASON_NEIGH_CREATEFAIL"
    )
    SKB_DROP_REASON_NEIGH_CREATEFAIL,

    /**
     * {@code SKB_DROP_REASON_NEIGH_FAILED = 58}
     */
    @EnumMember(
        value = 58L,
        name = "SKB_DROP_REASON_NEIGH_FAILED"
    )
    SKB_DROP_REASON_NEIGH_FAILED,

    /**
     * {@code SKB_DROP_REASON_NEIGH_QUEUEFULL = 59}
     */
    @EnumMember(
        value = 59L,
        name = "SKB_DROP_REASON_NEIGH_QUEUEFULL"
    )
    SKB_DROP_REASON_NEIGH_QUEUEFULL,

    /**
     * {@code SKB_DROP_REASON_NEIGH_DEAD = 60}
     */
    @EnumMember(
        value = 60L,
        name = "SKB_DROP_REASON_NEIGH_DEAD"
    )
    SKB_DROP_REASON_NEIGH_DEAD,

    /**
     * {@code SKB_DROP_REASON_NEIGH_HH_FILLFAIL = 61}
     */
    @EnumMember(
        value = 61L,
        name = "SKB_DROP_REASON_NEIGH_HH_FILLFAIL"
    )
    SKB_DROP_REASON_NEIGH_HH_FILLFAIL,

    /**
     * {@code SKB_DROP_REASON_TC_EGRESS = 62}
     */
    @EnumMember(
        value = 62L,
        name = "SKB_DROP_REASON_TC_EGRESS"
    )
    SKB_DROP_REASON_TC_EGRESS,

    /**
     * {@code SKB_DROP_REASON_SECURITY_HOOK = 63}
     */
    @EnumMember(
        value = 63L,
        name = "SKB_DROP_REASON_SECURITY_HOOK"
    )
    SKB_DROP_REASON_SECURITY_HOOK,

    /**
     * {@code SKB_DROP_REASON_QDISC_DROP = 64}
     */
    @EnumMember(
        value = 64L,
        name = "SKB_DROP_REASON_QDISC_DROP"
    )
    SKB_DROP_REASON_QDISC_DROP,

    /**
     * {@code SKB_DROP_REASON_QDISC_OVERLIMIT = 65}
     */
    @EnumMember(
        value = 65L,
        name = "SKB_DROP_REASON_QDISC_OVERLIMIT"
    )
    SKB_DROP_REASON_QDISC_OVERLIMIT,

    /**
     * {@code SKB_DROP_REASON_QDISC_CONGESTED = 66}
     */
    @EnumMember(
        value = 66L,
        name = "SKB_DROP_REASON_QDISC_CONGESTED"
    )
    SKB_DROP_REASON_QDISC_CONGESTED,

    /**
     * {@code SKB_DROP_REASON_CAKE_FLOOD = 67}
     */
    @EnumMember(
        value = 67L,
        name = "SKB_DROP_REASON_CAKE_FLOOD"
    )
    SKB_DROP_REASON_CAKE_FLOOD,

    /**
     * {@code SKB_DROP_REASON_FQ_BAND_LIMIT = 68}
     */
    @EnumMember(
        value = 68L,
        name = "SKB_DROP_REASON_FQ_BAND_LIMIT"
    )
    SKB_DROP_REASON_FQ_BAND_LIMIT,

    /**
     * {@code SKB_DROP_REASON_FQ_HORIZON_LIMIT = 69}
     */
    @EnumMember(
        value = 69L,
        name = "SKB_DROP_REASON_FQ_HORIZON_LIMIT"
    )
    SKB_DROP_REASON_FQ_HORIZON_LIMIT,

    /**
     * {@code SKB_DROP_REASON_FQ_FLOW_LIMIT = 70}
     */
    @EnumMember(
        value = 70L,
        name = "SKB_DROP_REASON_FQ_FLOW_LIMIT"
    )
    SKB_DROP_REASON_FQ_FLOW_LIMIT,

    /**
     * {@code SKB_DROP_REASON_CPU_BACKLOG = 71}
     */
    @EnumMember(
        value = 71L,
        name = "SKB_DROP_REASON_CPU_BACKLOG"
    )
    SKB_DROP_REASON_CPU_BACKLOG,

    /**
     * {@code SKB_DROP_REASON_XDP = 72}
     */
    @EnumMember(
        value = 72L,
        name = "SKB_DROP_REASON_XDP"
    )
    SKB_DROP_REASON_XDP,

    /**
     * {@code SKB_DROP_REASON_TC_INGRESS = 73}
     */
    @EnumMember(
        value = 73L,
        name = "SKB_DROP_REASON_TC_INGRESS"
    )
    SKB_DROP_REASON_TC_INGRESS,

    /**
     * {@code SKB_DROP_REASON_UNHANDLED_PROTO = 74}
     */
    @EnumMember(
        value = 74L,
        name = "SKB_DROP_REASON_UNHANDLED_PROTO"
    )
    SKB_DROP_REASON_UNHANDLED_PROTO,

    /**
     * {@code SKB_DROP_REASON_SKB_CSUM = 75}
     */
    @EnumMember(
        value = 75L,
        name = "SKB_DROP_REASON_SKB_CSUM"
    )
    SKB_DROP_REASON_SKB_CSUM,

    /**
     * {@code SKB_DROP_REASON_SKB_GSO_SEG = 76}
     */
    @EnumMember(
        value = 76L,
        name = "SKB_DROP_REASON_SKB_GSO_SEG"
    )
    SKB_DROP_REASON_SKB_GSO_SEG,

    /**
     * {@code SKB_DROP_REASON_SKB_UCOPY_FAULT = 77}
     */
    @EnumMember(
        value = 77L,
        name = "SKB_DROP_REASON_SKB_UCOPY_FAULT"
    )
    SKB_DROP_REASON_SKB_UCOPY_FAULT,

    /**
     * {@code SKB_DROP_REASON_DEV_HDR = 78}
     */
    @EnumMember(
        value = 78L,
        name = "SKB_DROP_REASON_DEV_HDR"
    )
    SKB_DROP_REASON_DEV_HDR,

    /**
     * {@code SKB_DROP_REASON_DEV_READY = 79}
     */
    @EnumMember(
        value = 79L,
        name = "SKB_DROP_REASON_DEV_READY"
    )
    SKB_DROP_REASON_DEV_READY,

    /**
     * {@code SKB_DROP_REASON_FULL_RING = 80}
     */
    @EnumMember(
        value = 80L,
        name = "SKB_DROP_REASON_FULL_RING"
    )
    SKB_DROP_REASON_FULL_RING,

    /**
     * {@code SKB_DROP_REASON_NOMEM = 81}
     */
    @EnumMember(
        value = 81L,
        name = "SKB_DROP_REASON_NOMEM"
    )
    SKB_DROP_REASON_NOMEM,

    /**
     * {@code SKB_DROP_REASON_HDR_TRUNC = 82}
     */
    @EnumMember(
        value = 82L,
        name = "SKB_DROP_REASON_HDR_TRUNC"
    )
    SKB_DROP_REASON_HDR_TRUNC,

    /**
     * {@code SKB_DROP_REASON_TAP_FILTER = 83}
     */
    @EnumMember(
        value = 83L,
        name = "SKB_DROP_REASON_TAP_FILTER"
    )
    SKB_DROP_REASON_TAP_FILTER,

    /**
     * {@code SKB_DROP_REASON_TAP_TXFILTER = 84}
     */
    @EnumMember(
        value = 84L,
        name = "SKB_DROP_REASON_TAP_TXFILTER"
    )
    SKB_DROP_REASON_TAP_TXFILTER,

    /**
     * {@code SKB_DROP_REASON_ICMP_CSUM = 85}
     */
    @EnumMember(
        value = 85L,
        name = "SKB_DROP_REASON_ICMP_CSUM"
    )
    SKB_DROP_REASON_ICMP_CSUM,

    /**
     * {@code SKB_DROP_REASON_INVALID_PROTO = 86}
     */
    @EnumMember(
        value = 86L,
        name = "SKB_DROP_REASON_INVALID_PROTO"
    )
    SKB_DROP_REASON_INVALID_PROTO,

    /**
     * {@code SKB_DROP_REASON_IP_INADDRERRORS = 87}
     */
    @EnumMember(
        value = 87L,
        name = "SKB_DROP_REASON_IP_INADDRERRORS"
    )
    SKB_DROP_REASON_IP_INADDRERRORS,

    /**
     * {@code SKB_DROP_REASON_IP_INNOROUTES = 88}
     */
    @EnumMember(
        value = 88L,
        name = "SKB_DROP_REASON_IP_INNOROUTES"
    )
    SKB_DROP_REASON_IP_INNOROUTES,

    /**
     * {@code SKB_DROP_REASON_IP_LOCAL_SOURCE = 89}
     */
    @EnumMember(
        value = 89L,
        name = "SKB_DROP_REASON_IP_LOCAL_SOURCE"
    )
    SKB_DROP_REASON_IP_LOCAL_SOURCE,

    /**
     * {@code SKB_DROP_REASON_IP_INVALID_SOURCE = 90}
     */
    @EnumMember(
        value = 90L,
        name = "SKB_DROP_REASON_IP_INVALID_SOURCE"
    )
    SKB_DROP_REASON_IP_INVALID_SOURCE,

    /**
     * {@code SKB_DROP_REASON_IP_LOCALNET = 91}
     */
    @EnumMember(
        value = 91L,
        name = "SKB_DROP_REASON_IP_LOCALNET"
    )
    SKB_DROP_REASON_IP_LOCALNET,

    /**
     * {@code SKB_DROP_REASON_IP_INVALID_DEST = 92}
     */
    @EnumMember(
        value = 92L,
        name = "SKB_DROP_REASON_IP_INVALID_DEST"
    )
    SKB_DROP_REASON_IP_INVALID_DEST,

    /**
     * {@code SKB_DROP_REASON_PKT_TOO_BIG = 93}
     */
    @EnumMember(
        value = 93L,
        name = "SKB_DROP_REASON_PKT_TOO_BIG"
    )
    SKB_DROP_REASON_PKT_TOO_BIG,

    /**
     * {@code SKB_DROP_REASON_DUP_FRAG = 94}
     */
    @EnumMember(
        value = 94L,
        name = "SKB_DROP_REASON_DUP_FRAG"
    )
    SKB_DROP_REASON_DUP_FRAG,

    /**
     * {@code SKB_DROP_REASON_FRAG_REASM_TIMEOUT = 95}
     */
    @EnumMember(
        value = 95L,
        name = "SKB_DROP_REASON_FRAG_REASM_TIMEOUT"
    )
    SKB_DROP_REASON_FRAG_REASM_TIMEOUT,

    /**
     * {@code SKB_DROP_REASON_FRAG_TOO_FAR = 96}
     */
    @EnumMember(
        value = 96L,
        name = "SKB_DROP_REASON_FRAG_TOO_FAR"
    )
    SKB_DROP_REASON_FRAG_TOO_FAR,

    /**
     * {@code SKB_DROP_REASON_TCP_MINTTL = 97}
     */
    @EnumMember(
        value = 97L,
        name = "SKB_DROP_REASON_TCP_MINTTL"
    )
    SKB_DROP_REASON_TCP_MINTTL,

    /**
     * {@code SKB_DROP_REASON_IPV6_BAD_EXTHDR = 98}
     */
    @EnumMember(
        value = 98L,
        name = "SKB_DROP_REASON_IPV6_BAD_EXTHDR"
    )
    SKB_DROP_REASON_IPV6_BAD_EXTHDR,

    /**
     * {@code SKB_DROP_REASON_IPV6_NDISC_FRAG = 99}
     */
    @EnumMember(
        value = 99L,
        name = "SKB_DROP_REASON_IPV6_NDISC_FRAG"
    )
    SKB_DROP_REASON_IPV6_NDISC_FRAG,

    /**
     * {@code SKB_DROP_REASON_IPV6_NDISC_HOP_LIMIT = 100}
     */
    @EnumMember(
        value = 100L,
        name = "SKB_DROP_REASON_IPV6_NDISC_HOP_LIMIT"
    )
    SKB_DROP_REASON_IPV6_NDISC_HOP_LIMIT,

    /**
     * {@code SKB_DROP_REASON_IPV6_NDISC_BAD_CODE = 101}
     */
    @EnumMember(
        value = 101L,
        name = "SKB_DROP_REASON_IPV6_NDISC_BAD_CODE"
    )
    SKB_DROP_REASON_IPV6_NDISC_BAD_CODE,

    /**
     * {@code SKB_DROP_REASON_IPV6_NDISC_BAD_OPTIONS = 102}
     */
    @EnumMember(
        value = 102L,
        name = "SKB_DROP_REASON_IPV6_NDISC_BAD_OPTIONS"
    )
    SKB_DROP_REASON_IPV6_NDISC_BAD_OPTIONS,

    /**
     * {@code SKB_DROP_REASON_IPV6_NDISC_NS_OTHERHOST = 103}
     */
    @EnumMember(
        value = 103L,
        name = "SKB_DROP_REASON_IPV6_NDISC_NS_OTHERHOST"
    )
    SKB_DROP_REASON_IPV6_NDISC_NS_OTHERHOST,

    /**
     * {@code SKB_DROP_REASON_QUEUE_PURGE = 104}
     */
    @EnumMember(
        value = 104L,
        name = "SKB_DROP_REASON_QUEUE_PURGE"
    )
    SKB_DROP_REASON_QUEUE_PURGE,

    /**
     * {@code SKB_DROP_REASON_TC_COOKIE_ERROR = 105}
     */
    @EnumMember(
        value = 105L,
        name = "SKB_DROP_REASON_TC_COOKIE_ERROR"
    )
    SKB_DROP_REASON_TC_COOKIE_ERROR,

    /**
     * {@code SKB_DROP_REASON_PACKET_SOCK_ERROR = 106}
     */
    @EnumMember(
        value = 106L,
        name = "SKB_DROP_REASON_PACKET_SOCK_ERROR"
    )
    SKB_DROP_REASON_PACKET_SOCK_ERROR,

    /**
     * {@code SKB_DROP_REASON_TC_CHAIN_NOTFOUND = 107}
     */
    @EnumMember(
        value = 107L,
        name = "SKB_DROP_REASON_TC_CHAIN_NOTFOUND"
    )
    SKB_DROP_REASON_TC_CHAIN_NOTFOUND,

    /**
     * {@code SKB_DROP_REASON_TC_RECLASSIFY_LOOP = 108}
     */
    @EnumMember(
        value = 108L,
        name = "SKB_DROP_REASON_TC_RECLASSIFY_LOOP"
    )
    SKB_DROP_REASON_TC_RECLASSIFY_LOOP,

    /**
     * {@code SKB_DROP_REASON_VXLAN_INVALID_HDR = 109}
     */
    @EnumMember(
        value = 109L,
        name = "SKB_DROP_REASON_VXLAN_INVALID_HDR"
    )
    SKB_DROP_REASON_VXLAN_INVALID_HDR,

    /**
     * {@code SKB_DROP_REASON_VXLAN_VNI_NOT_FOUND = 110}
     */
    @EnumMember(
        value = 110L,
        name = "SKB_DROP_REASON_VXLAN_VNI_NOT_FOUND"
    )
    SKB_DROP_REASON_VXLAN_VNI_NOT_FOUND,

    /**
     * {@code SKB_DROP_REASON_MAC_INVALID_SOURCE = 111}
     */
    @EnumMember(
        value = 111L,
        name = "SKB_DROP_REASON_MAC_INVALID_SOURCE"
    )
    SKB_DROP_REASON_MAC_INVALID_SOURCE,

    /**
     * {@code SKB_DROP_REASON_VXLAN_ENTRY_EXISTS = 112}
     */
    @EnumMember(
        value = 112L,
        name = "SKB_DROP_REASON_VXLAN_ENTRY_EXISTS"
    )
    SKB_DROP_REASON_VXLAN_ENTRY_EXISTS,

    /**
     * {@code SKB_DROP_REASON_NO_TX_TARGET = 113}
     */
    @EnumMember(
        value = 113L,
        name = "SKB_DROP_REASON_NO_TX_TARGET"
    )
    SKB_DROP_REASON_NO_TX_TARGET,

    /**
     * {@code SKB_DROP_REASON_IP_TUNNEL_ECN = 114}
     */
    @EnumMember(
        value = 114L,
        name = "SKB_DROP_REASON_IP_TUNNEL_ECN"
    )
    SKB_DROP_REASON_IP_TUNNEL_ECN,

    /**
     * {@code SKB_DROP_REASON_TUNNEL_TXINFO = 115}
     */
    @EnumMember(
        value = 115L,
        name = "SKB_DROP_REASON_TUNNEL_TXINFO"
    )
    SKB_DROP_REASON_TUNNEL_TXINFO,

    /**
     * {@code SKB_DROP_REASON_LOCAL_MAC = 116}
     */
    @EnumMember(
        value = 116L,
        name = "SKB_DROP_REASON_LOCAL_MAC"
    )
    SKB_DROP_REASON_LOCAL_MAC,

    /**
     * {@code SKB_DROP_REASON_ARP_PVLAN_DISABLE = 117}
     */
    @EnumMember(
        value = 117L,
        name = "SKB_DROP_REASON_ARP_PVLAN_DISABLE"
    )
    SKB_DROP_REASON_ARP_PVLAN_DISABLE,

    /**
     * {@code SKB_DROP_REASON_MAC_IEEE_MAC_CONTROL = 118}
     */
    @EnumMember(
        value = 118L,
        name = "SKB_DROP_REASON_MAC_IEEE_MAC_CONTROL"
    )
    SKB_DROP_REASON_MAC_IEEE_MAC_CONTROL,

    /**
     * {@code SKB_DROP_REASON_BRIDGE_INGRESS_STP_STATE = 119}
     */
    @EnumMember(
        value = 119L,
        name = "SKB_DROP_REASON_BRIDGE_INGRESS_STP_STATE"
    )
    SKB_DROP_REASON_BRIDGE_INGRESS_STP_STATE,

    /**
     * {@code SKB_DROP_REASON_CAN_RX_INVALID_FRAME = 120}
     */
    @EnumMember(
        value = 120L,
        name = "SKB_DROP_REASON_CAN_RX_INVALID_FRAME"
    )
    SKB_DROP_REASON_CAN_RX_INVALID_FRAME,

    /**
     * {@code SKB_DROP_REASON_CANFD_RX_INVALID_FRAME = 121}
     */
    @EnumMember(
        value = 121L,
        name = "SKB_DROP_REASON_CANFD_RX_INVALID_FRAME"
    )
    SKB_DROP_REASON_CANFD_RX_INVALID_FRAME,

    /**
     * {@code SKB_DROP_REASON_CANXL_RX_INVALID_FRAME = 122}
     */
    @EnumMember(
        value = 122L,
        name = "SKB_DROP_REASON_CANXL_RX_INVALID_FRAME"
    )
    SKB_DROP_REASON_CANXL_RX_INVALID_FRAME,

    /**
     * {@code SKB_DROP_REASON_PFMEMALLOC = 123}
     */
    @EnumMember(
        value = 123L,
        name = "SKB_DROP_REASON_PFMEMALLOC"
    )
    SKB_DROP_REASON_PFMEMALLOC,

    /**
     * {@code SKB_DROP_REASON_DUALPI2_STEP_DROP = 124}
     */
    @EnumMember(
        value = 124L,
        name = "SKB_DROP_REASON_DUALPI2_STEP_DROP"
    )
    SKB_DROP_REASON_DUALPI2_STEP_DROP,

    /**
     * {@code SKB_DROP_REASON_MAX = 125}
     */
    @EnumMember(
        value = 125L,
        name = "SKB_DROP_REASON_MAX"
    )
    SKB_DROP_REASON_MAX,

    /**
     * {@code SKB_DROP_REASON_SUBSYS_MASK = -65536}
     */
    @EnumMember(
        value = -65536L,
        name = "SKB_DROP_REASON_SUBSYS_MASK"
    )
    SKB_DROP_REASON_SUBSYS_MASK
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct skb_frag"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class skb_frag extends Struct {
    public @Unsigned @OriginalName("netmem_ref") long netmem;

    public @Unsigned int len;

    public @Unsigned int offset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct skb_shared_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class skb_shared_info extends Struct {
    public char flags;

    public char meta_len;

    public char nr_frags;

    public char tx_flags;

    public @Unsigned short gso_size;

    public @Unsigned short gso_segs;

    public Ptr<sk_buff> frag_list;

    @InlineUnion(17851)
    public skb_shared_hwtstamps hwtstamps;

    @InlineUnion(17851)
    public xsk_tx_metadata_compl xsk_meta;

    public @Unsigned int gso_type;

    public @Unsigned int tskey;

    public atomic_t dataref;

    @InlineUnion(17853)
    public anon_member_of_anon_member_of_skb_shared_info anon11$0;

    @InlineUnion(17853)
    public Ptr<?> destructor_arg;

    public @OriginalName("skb_frag_t") skb_frag @Size(17) [] frags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum skb_tstamp_type"
  )
  public enum skb_tstamp_type implements Enum<skb_tstamp_type>, TypedEnum<skb_tstamp_type, java.lang. @Unsigned Integer> {
    /**
     * {@code SKB_CLOCK_REALTIME = 0}
     */
    @EnumMember(
        value = 0L,
        name = "SKB_CLOCK_REALTIME"
    )
    SKB_CLOCK_REALTIME,

    /**
     * {@code SKB_CLOCK_MONOTONIC = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SKB_CLOCK_MONOTONIC"
    )
    SKB_CLOCK_MONOTONIC,

    /**
     * {@code SKB_CLOCK_TAI = 2}
     */
    @EnumMember(
        value = 2L,
        name = "SKB_CLOCK_TAI"
    )
    SKB_CLOCK_TAI,

    /**
     * {@code __SKB_CLOCK_MAX = 2}
     */
    @EnumMember(
        value = 2L,
        name = "__SKB_CLOCK_MAX"
    )
    __SKB_CLOCK_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct skb_seq_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class skb_seq_state extends Struct {
    public @Unsigned int lower_offset;

    public @Unsigned int upper_offset;

    public @Unsigned int frag_idx;

    public @Unsigned int stepped_offset;

    public Ptr<sk_buff> root_skb;

    public Ptr<sk_buff> cur_skb;

    public Ptr<java.lang.Character> frag_data;

    public @Unsigned int frag_off;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct skb_gso_cb"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class skb_gso_cb extends Struct {
    @InlineUnion(57049)
    public int mac_offset;

    @InlineUnion(57049)
    public int data_offset;

    public int encap_level;

    public @Unsigned @OriginalName("__wsum") int csum;

    public @Unsigned short csum_start;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum skb_drop_reason_subsys"
  )
  public enum skb_drop_reason_subsys implements Enum<skb_drop_reason_subsys>, TypedEnum<skb_drop_reason_subsys, java.lang. @Unsigned Integer> {
    /**
     * {@code SKB_DROP_REASON_SUBSYS_CORE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "SKB_DROP_REASON_SUBSYS_CORE"
    )
    SKB_DROP_REASON_SUBSYS_CORE,

    /**
     * {@code SKB_DROP_REASON_SUBSYS_MAC80211_UNUSABLE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SKB_DROP_REASON_SUBSYS_MAC80211_UNUSABLE"
    )
    SKB_DROP_REASON_SUBSYS_MAC80211_UNUSABLE,

    /**
     * {@code SKB_DROP_REASON_SUBSYS_OPENVSWITCH = 2}
     */
    @EnumMember(
        value = 2L,
        name = "SKB_DROP_REASON_SUBSYS_OPENVSWITCH"
    )
    SKB_DROP_REASON_SUBSYS_OPENVSWITCH,

    /**
     * {@code SKB_DROP_REASON_SUBSYS_NUM = 3}
     */
    @EnumMember(
        value = 3L,
        name = "SKB_DROP_REASON_SUBSYS_NUM"
    )
    SKB_DROP_REASON_SUBSYS_NUM
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct skb_free_array"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class skb_free_array extends Struct {
    public @Unsigned int skb_count;

    public Ptr<?> @Size(16) [] skb_array;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct skb_array"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class skb_array extends Struct {
    public ptr_ring ring;
  }
}
