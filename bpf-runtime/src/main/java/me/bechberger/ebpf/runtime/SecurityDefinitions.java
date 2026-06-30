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
import static me.bechberger.ebpf.runtime.SkbDefinitions.*;
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
 * Generated class for BPF runtime types that start with security
 */
@java.lang.SuppressWarnings("unused")
public final class SecurityDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction("__security_genfs_sid($arg1, (const u8 *)$arg2, (const u8 *)$arg3, $arg4, $arg5)")
  public static int __security_genfs_sid(Ptr<selinux_policy> policy, String fstype, String path,
      @Unsigned short orig_sclass, Ptr<java.lang. @Unsigned Integer> sid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_add_hooks($arg1, $arg2, (const struct lsm_id *)$arg3)")
  public static void security_add_hooks(Ptr<security_hook_list> hooks, int count,
      Ptr<lsm_id> lsmid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_audit_rule_free(Ptr<?> lsmrule) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_audit_rule_init(@Unsigned int field, @Unsigned int op, String rulestr,
      Ptr<Ptr<?>> lsmrule, @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_audit_rule_known(Ptr<audit_krule> krule) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_audit_rule_match(Ptr<lsm_prop> prop, @Unsigned int field,
      @Unsigned int op, Ptr<?> lsmrule) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_bdev_alloc(Ptr<block_device> bdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_bdev_free(Ptr<block_device> bdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_bdev_setintegrity($arg1, $arg2, (const void *)$arg3, $arg4)")
  public static int security_bdev_setintegrity(Ptr<block_device> bdev, lsm_integrity_type type,
      Ptr<?> value, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_binder_set_context_mgr((const struct cred *)$arg1)")
  public static int security_binder_set_context_mgr(Ptr<cred> mgr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_binder_transaction((const struct cred *)$arg1, (const struct cred *)$arg2)")
  public static int security_binder_transaction(Ptr<cred> from, Ptr<cred> to) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_binder_transfer_binder((const struct cred *)$arg1, (const struct cred *)$arg2)")
  public static int security_binder_transfer_binder(Ptr<cred> from, Ptr<cred> to) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_binder_transfer_file((const struct cred *)$arg1, (const struct cred *)$arg2, (const struct file *)$arg3)")
  public static int security_binder_transfer_file(Ptr<cred> from, Ptr<cred> to, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_bounded_transition(@Unsigned int old_sid, @Unsigned int new_sid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_bpf(int cmd, Ptr<bpf_attr> attr, @Unsigned int size, boolean kernel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_bpf_map(Ptr<bpf_map> map,
      @Unsigned @OriginalName("fmode_t") int fmode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_bpf_map_create(Ptr<bpf_map> map, Ptr<bpf_attr> attr,
      Ptr<bpf_token> token, boolean kernel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_bpf_map_free(Ptr<bpf_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_bpf_prog(Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_bpf_prog_free(Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_bpf_prog_load(Ptr<bpf_prog> prog, Ptr<bpf_attr> attr,
      Ptr<bpf_token> token, boolean kernel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_bpf_token_capable((const struct bpf_token *)$arg1, $arg2)")
  public static int security_bpf_token_capable(Ptr<bpf_token> token, int cap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_bpf_token_cmd((const struct bpf_token *)$arg1, $arg2)")
  public static int security_bpf_token_cmd(Ptr<bpf_token> token, bpf_cmd cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_bpf_token_create($arg1, $arg2, (const struct path *)$arg3)")
  public static int security_bpf_token_create(Ptr<bpf_token> token, Ptr<bpf_attr> attr,
      Ptr<path> path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_bpf_token_free(Ptr<bpf_token> token) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_bprm_check(Ptr<linux_binprm> bprm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_bprm_committed_creds((const struct linux_binprm *)$arg1)")
  public static void security_bprm_committed_creds(Ptr<linux_binprm> bprm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_bprm_committing_creds((const struct linux_binprm *)$arg1)")
  public static void security_bprm_committing_creds(Ptr<linux_binprm> bprm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_bprm_creds_for_exec(Ptr<linux_binprm> bprm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_bprm_creds_from_file($arg1, (const struct file *)$arg2)")
  public static int security_bprm_creds_from_file(Ptr<linux_binprm> bprm, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_capable((const struct cred *)$arg1, $arg2, $arg3, $arg4)")
  public static int security_capable(Ptr<cred> cred, Ptr<user_namespace> ns, int cap,
      @Unsigned int opts) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_capget((const struct task_struct *)$arg1, $arg2, $arg3, $arg4)")
  public static int security_capget(Ptr<task_struct> target, Ptr<kernel_cap_t> effective,
      Ptr<kernel_cap_t> inheritable, Ptr<kernel_cap_t> permitted) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_capset($arg1, (const struct cred *)$arg2, (const struct {\n"
          + "  long long unsigned int val;\n"
          + "} *)$arg3, (const struct {\n"
          + "  long long unsigned int val;\n"
          + "} *)$arg4, (const struct {\n"
          + "  long long unsigned int val;\n"
          + "} *)$arg5)")
  public static int security_capset(Ptr<cred> _new, Ptr<cred> old, Ptr<kernel_cap_t> effective,
      Ptr<kernel_cap_t> inheritable, Ptr<kernel_cap_t> permitted) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_change_sid(@Unsigned int ssid, @Unsigned int tsid,
      @Unsigned short tclass, Ptr<java.lang. @Unsigned Integer> out_sid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_compute_av(@Unsigned int ssid, @Unsigned int tsid,
      @Unsigned short orig_tclass, Ptr<av_decision> avd, Ptr<extended_perms> xperms) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_compute_av_user(@Unsigned int ssid, @Unsigned int tsid,
      @Unsigned short tclass, Ptr<av_decision> avd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_compute_sid($arg1, $arg2, $arg3, $arg4, (const u8 *)$arg5, $arg6, $arg7)")
  public static int security_compute_sid(@Unsigned int ssid, @Unsigned int tsid,
      @Unsigned short orig_tclass, @Unsigned short specified, String objname,
      Ptr<java.lang. @Unsigned Integer> out_sid, boolean kern) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_compute_validatetrans(@Unsigned int oldsid, @Unsigned int newsid,
      @Unsigned int tasksid, @Unsigned short orig_tclass, boolean user) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_compute_xperms_decision(@Unsigned int ssid, @Unsigned int tsid,
      @Unsigned short orig_tclass, char driver, char base_perm,
      Ptr<extended_perms_decision> xpermd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_context_str_to_sid((const u8 *)$arg1, $arg2, $arg3)")
  public static int security_context_str_to_sid(String scontext,
      Ptr<java.lang. @Unsigned Integer> sid, @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_context_to_sid((const u8 *)$arg1, $arg2, $arg3, $arg4)")
  public static int security_context_to_sid(String scontext, @Unsigned int scontext_len,
      Ptr<java.lang. @Unsigned Integer> sid, @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_context_to_sid_core((const u8 *)$arg1, $arg2, $arg3, $arg4, $arg5, $arg6)")
  public static int security_context_to_sid_core(String scontext, @Unsigned int scontext_len,
      Ptr<java.lang. @Unsigned Integer> sid, @Unsigned int def_sid,
      @Unsigned @OriginalName("gfp_t") int gfp_flags, int force) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_context_to_sid_default((const u8 *)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int security_context_to_sid_default(String scontext, @Unsigned int scontext_len,
      Ptr<java.lang. @Unsigned Integer> sid, @Unsigned int def_sid,
      @Unsigned @OriginalName("gfp_t") int gfp_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_context_to_sid_force((const u8 *)$arg1, $arg2, $arg3)")
  public static int security_context_to_sid_force(String scontext, @Unsigned int scontext_len,
      Ptr<java.lang. @Unsigned Integer> sid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_create_user_ns((const struct cred *)$arg1)")
  public static int security_create_user_ns(Ptr<cred> cred) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_cred_alloc_blank(Ptr<cred> cred,
      @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_cred_free(Ptr<cred> cred) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_cred_getlsmprop((const struct cred *)$arg1, $arg2)")
  public static void security_cred_getlsmprop(Ptr<cred> c, Ptr<lsm_prop> prop) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_cred_getsecid((const struct cred *)$arg1, $arg2)")
  public static void security_cred_getsecid(Ptr<cred> c, Ptr<java.lang. @Unsigned Integer> secid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_current_getlsmprop_subj(Ptr<lsm_prop> prop) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_d_instantiate(Ptr<dentry> dentry, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_dentry_create_files_as($arg1, $arg2, $arg3, (const struct cred *)$arg4, $arg5)")
  public static int security_dentry_create_files_as(Ptr<dentry> dentry, int mode, Ptr<qstr> name,
      Ptr<cred> old, Ptr<cred> _new) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_dentry_init_security($arg1, $arg2, (const struct qstr *)$arg3, (const u8**)$arg4, $arg5)")
  public static int security_dentry_init_security(Ptr<dentry> dentry, int mode, Ptr<qstr> name,
      Ptr<String> xattr_name, Ptr<lsm_context> lsmctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_disable(Ptr<nvdimm> nvdimm, @Unsigned int keyid,
      nvdimm_passphrase_type pass_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_dump_masked_av($arg1, $arg2, $arg3, $arg4, $arg5, (const u8 *)$arg6)")
  public static void security_dump_masked_av(Ptr<policydb> policydb, Ptr<context> scontext,
      Ptr<context> tcontext, @Unsigned short tclass, @Unsigned int permissions, String reason) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_erase(Ptr<nvdimm> nvdimm, @Unsigned int keyid,
      nvdimm_passphrase_type pass_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_file_alloc(Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_file_fcntl(Ptr<file> file, @Unsigned int cmd, @Unsigned long arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_file_free(Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_file_ioctl(Ptr<file> file, @Unsigned int cmd, @Unsigned long arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_file_ioctl_compat(Ptr<file> file, @Unsigned int cmd,
      @Unsigned long arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_file_lock(Ptr<file> file, @Unsigned int cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_file_mprotect(Ptr<vm_area_struct> vma, @Unsigned long reqprot,
      @Unsigned long prot) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_file_open(Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_file_permission(Ptr<file> file, int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_file_post_open(Ptr<file> file, int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_file_receive(Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_file_release(Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_file_send_sigiotask(Ptr<task_struct> tsk, Ptr<fown_struct> fown,
      int sig) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_file_set_fowner(Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_file_truncate(Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_free_mnt_opts(Ptr<Ptr<?>> mnt_opts) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_fs_context_dup(Ptr<fs_context> fc, Ptr<fs_context> src_fc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_fs_context_parse_param(Ptr<fs_context> fc, Ptr<fs_parameter> param) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_fs_context_submount(Ptr<fs_context> fc, Ptr<super_block> reference) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_fs_use(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_genfs_sid((const u8 *)$arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static int security_genfs_sid(String fstype, String path, @Unsigned short orig_sclass,
      Ptr<java.lang. @Unsigned Integer> sid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_get_allow_unknown() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_get_bool_value(@Unsigned int index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_get_bools(Ptr<selinux_policy> policy,
      Ptr<java.lang. @Unsigned Integer> len, Ptr<Ptr<String>> names,
      Ptr<Ptr<java.lang.Integer>> values) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_get_classes(Ptr<selinux_policy> policy, Ptr<Ptr<String>> classes,
      Ptr<java.lang. @Unsigned Integer> nclasses) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)security_get_initial_sid_context($arg1))")
  public static String security_get_initial_sid_context(@Unsigned int sid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_get_permissions($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static int security_get_permissions(Ptr<selinux_policy> policy, String _class,
      Ptr<Ptr<String>> perms, Ptr<java.lang. @Unsigned Integer> nperms) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_get_reject_unknown() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_get_user_sids($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static int security_get_user_sids(@Unsigned int fromsid, String username,
      Ptr<Ptr<java.lang. @Unsigned Integer>> sids, Ptr<java.lang. @Unsigned Integer> nel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_getprocattr($arg1, $arg2, (const u8 *)$arg3, $arg4)")
  public static int security_getprocattr(Ptr<task_struct> p, int lsmid, String name,
      Ptr<String> value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_getselfattr(@Unsigned int attr, Ptr<lsm_ctx> uctx,
      Ptr<java.lang. @Unsigned Integer> size, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_ib_alloc_security(Ptr<Ptr<?>> sec) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_ib_endport_manage_subnet($arg1, (const u8 *)$arg2, $arg3)")
  public static int security_ib_endport_manage_subnet(Ptr<?> sec, String dev_name, char port_num) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_ib_endport_sid((const u8 *)$arg1, $arg2, $arg3)")
  public static int security_ib_endport_sid(String dev_name, char port_num,
      Ptr<java.lang. @Unsigned Integer> out_sid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_ib_free_security(Ptr<?> sec) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_ib_pkey_access(Ptr<?> sec, @Unsigned long subnet_prefix,
      @Unsigned short pkey) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_ib_pkey_sid(@Unsigned long subnet_prefix, @Unsigned short pkey_num,
      Ptr<java.lang. @Unsigned Integer> out_sid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_inet_conn_established(Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_inet_conn_request((const struct sock *)$arg1, $arg2, $arg3)")
  public static int security_inet_conn_request(Ptr<sock> sk, Ptr<sk_buff> skb,
      Ptr<request_sock> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_inet_csk_clone($arg1, (const struct request_sock *)$arg2)")
  public static void security_inet_csk_clone(Ptr<sock> newsk, Ptr<request_sock> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_initramfs_populated() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_inode_alloc(Ptr<inode> inode,
      @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_inode_copy_up(Ptr<dentry> src, Ptr<Ptr<cred>> _new) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_inode_copy_up_xattr($arg1, (const u8 *)$arg2)")
  public static int security_inode_copy_up_xattr(Ptr<dentry> src, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_inode_create(Ptr<inode> dir, Ptr<dentry> dentry,
      @Unsigned @OriginalName("umode_t") short mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_inode_file_getattr(Ptr<dentry> dentry, Ptr<file_kattr> fa) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_inode_file_setattr(Ptr<dentry> dentry, Ptr<file_kattr> fa) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_inode_follow_link(Ptr<dentry> dentry, Ptr<inode> inode, boolean rcu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_inode_free(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_inode_get_acl($arg1, $arg2, (const u8 *)$arg3)")
  public static int security_inode_get_acl(Ptr<mnt_idmap> idmap, Ptr<dentry> dentry,
      String acl_name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_inode_getattr((const struct path *)$arg1)")
  public static int security_inode_getattr(Ptr<path> path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_inode_getlsmprop(Ptr<inode> inode, Ptr<lsm_prop> prop) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_inode_getsecctx(Ptr<inode> inode, Ptr<lsm_context> cp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_inode_getsecurity($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5)")
  public static int security_inode_getsecurity(Ptr<mnt_idmap> idmap, Ptr<inode> inode, String name,
      Ptr<Ptr<?>> buffer, boolean alloc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_inode_getxattr($arg1, (const u8 *)$arg2)")
  public static int security_inode_getxattr(Ptr<dentry> dentry, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_inode_init_security($arg1, $arg2, (const struct qstr *)$arg3, (const int (struct inode*, const struct xattr*, void*)*)$arg4, $arg5)")
  public static int security_inode_init_security(Ptr<inode> inode, Ptr<inode> dir, Ptr<qstr> qstr,
      @OriginalName("initxattrs") Ptr<?> initxattrs, Ptr<?> fs_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_inode_init_security_anon($arg1, (const struct qstr *)$arg2, (const struct inode *)$arg3)")
  public static int security_inode_init_security_anon(Ptr<inode> inode, Ptr<qstr> name,
      Ptr<inode> context_inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_inode_invalidate_secctx(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_inode_killpriv(Ptr<mnt_idmap> idmap, Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_inode_link(Ptr<dentry> old_dentry, Ptr<inode> dir,
      Ptr<dentry> new_dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_inode_listsecurity(Ptr<inode> inode, String buffer,
      @Unsigned long buffer_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_inode_listxattr(Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_inode_mkdir(Ptr<inode> dir, Ptr<dentry> dentry,
      @Unsigned @OriginalName("umode_t") short mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_inode_mknod(Ptr<inode> dir, Ptr<dentry> dentry,
      @Unsigned @OriginalName("umode_t") short mode, @Unsigned @OriginalName("dev_t") int dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_inode_need_killpriv(Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_inode_notifysecctx(Ptr<inode> inode, Ptr<?> ctx,
      @Unsigned int ctxlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_inode_permission(Ptr<inode> inode, int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_inode_post_create_tmpfile(Ptr<mnt_idmap> idmap, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_inode_post_remove_acl($arg1, $arg2, (const u8 *)$arg3)")
  public static void security_inode_post_remove_acl(Ptr<mnt_idmap> idmap, Ptr<dentry> dentry,
      String acl_name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_inode_post_removexattr($arg1, (const u8 *)$arg2)")
  public static void security_inode_post_removexattr(Ptr<dentry> dentry, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_inode_post_set_acl($arg1, (const u8 *)$arg2, $arg3)")
  public static void security_inode_post_set_acl(Ptr<dentry> dentry, String acl_name,
      Ptr<posix_acl> kacl) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_inode_post_setattr(Ptr<mnt_idmap> idmap, Ptr<dentry> dentry,
      int ia_valid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_inode_post_setxattr($arg1, (const u8 *)$arg2, (const void *)$arg3, $arg4, $arg5)")
  public static void security_inode_post_setxattr(Ptr<dentry> dentry, String name, Ptr<?> value,
      @Unsigned long size, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_inode_readlink(Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_inode_remove_acl($arg1, $arg2, (const u8 *)$arg3)")
  public static int security_inode_remove_acl(Ptr<mnt_idmap> idmap, Ptr<dentry> dentry,
      String acl_name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_inode_removexattr($arg1, $arg2, (const u8 *)$arg3)")
  public static int security_inode_removexattr(Ptr<mnt_idmap> idmap, Ptr<dentry> dentry,
      String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_inode_rename(Ptr<inode> old_dir, Ptr<dentry> old_dentry,
      Ptr<inode> new_dir, Ptr<dentry> new_dentry, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_inode_rmdir(Ptr<inode> dir, Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_inode_set_acl($arg1, $arg2, (const u8 *)$arg3, $arg4)")
  public static int security_inode_set_acl(Ptr<mnt_idmap> idmap, Ptr<dentry> dentry,
      String acl_name, Ptr<posix_acl> kacl) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_inode_setattr(Ptr<mnt_idmap> idmap, Ptr<dentry> dentry,
      Ptr<iattr> attr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_inode_setintegrity((const struct inode *)$arg1, $arg2, (const void *)$arg3, $arg4)")
  public static int security_inode_setintegrity(Ptr<inode> inode, lsm_integrity_type type,
      Ptr<?> value, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_inode_setsecctx(Ptr<dentry> dentry, Ptr<?> ctx, @Unsigned int ctxlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_inode_setsecurity($arg1, (const u8 *)$arg2, (const void *)$arg3, $arg4, $arg5)")
  public static int security_inode_setsecurity(Ptr<inode> inode, String name, Ptr<?> value,
      @Unsigned long size, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_inode_setxattr($arg1, $arg2, (const u8 *)$arg3, (const void *)$arg4, $arg5, $arg6)")
  public static int security_inode_setxattr(Ptr<mnt_idmap> idmap, Ptr<dentry> dentry, String name,
      Ptr<?> value, @Unsigned long size, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_inode_symlink($arg1, $arg2, (const u8 *)$arg3)")
  public static int security_inode_symlink(Ptr<inode> dir, Ptr<dentry> dentry, String old_name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_inode_unlink(Ptr<inode> dir, Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_ipc_getlsmprop(Ptr<kern_ipc_perm> ipcp, Ptr<lsm_prop> prop) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_ipc_permission(Ptr<kern_ipc_perm> ipcp, short flag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_ismaclabel((const u8 *)$arg1)")
  public static int security_ismaclabel(String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_kernel_act_as(Ptr<cred> _new, @Unsigned int secid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_kernel_create_files_as(Ptr<cred> _new, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_kernel_load_data(kernel_load_data_id id, boolean contents) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_kernel_module_request(String kmod_name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_kernel_post_load_data(String buf, @OriginalName("loff_t") long size,
      kernel_load_data_id id, String description) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_kernel_post_read_file(Ptr<file> file, String buf,
      @OriginalName("loff_t") long size, kernel_read_file_id id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_kernel_read_file(Ptr<file> file, kernel_read_file_id id,
      boolean contents) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_kernfs_init_security(Ptr<kernfs_node> kn_dir, Ptr<kernfs_node> kn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_key_alloc($arg1, (const struct cred *)$arg2, $arg3)")
  public static int security_key_alloc(Ptr<key> key, Ptr<cred> cred, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_key_free(Ptr<key> key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_key_getsecurity(Ptr<key> key, Ptr<String> buffer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_key_permission($arg1, (const struct cred *)$arg2, $arg3)")
  public static int security_key_permission(
      @OriginalName("__key_reference_with_attributes") @OriginalName("__key_reference_with_attributes") @OriginalName("key_ref_t") Ptr<?> key_ref,
      Ptr<cred> cred, key_need_perm need_perm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_key_post_create_or_update($arg1, $arg2, (const void *)$arg3, $arg4, $arg5, $arg6)")
  public static void security_key_post_create_or_update(Ptr<key> keyring, Ptr<key> key,
      Ptr<?> payload, @Unsigned long payload_len, @Unsigned long flags, boolean create) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_load_policy(Ptr<?> data, @Unsigned long len,
      Ptr<selinux_load_state> load_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_lock_kernel_down((const u8 *)$arg1, $arg2)")
  public static int security_lock_kernel_down(String where, lockdown_reason level) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_locked_down(lockdown_reason what) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_lsmprop_to_secctx(Ptr<lsm_prop> prop, Ptr<lsm_context> cp, int lsmid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_member_sid(@Unsigned int ssid, @Unsigned int tsid,
      @Unsigned short tclass, Ptr<java.lang. @Unsigned Integer> out_sid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_mls_enabled() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_mmap_addr(@Unsigned long addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_mmap_file(Ptr<file> file, @Unsigned long prot, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_move_mount((const struct path *)$arg1, (const struct path *)$arg2)")
  public static int security_move_mount(Ptr<path> from_path, Ptr<path> to_path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_mptcp_add_subflow(Ptr<sock> sk, Ptr<sock> ssk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_msg_msg_alloc(Ptr<msg_msg> msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_msg_msg_free(Ptr<msg_msg> msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_msg_queue_alloc(Ptr<kern_ipc_perm> msq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_msg_queue_associate(Ptr<kern_ipc_perm> msq, int msqflg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_msg_queue_free(Ptr<kern_ipc_perm> msq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_msg_queue_msgctl(Ptr<kern_ipc_perm> msq, int cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_msg_queue_msgrcv(Ptr<kern_ipc_perm> msq, Ptr<msg_msg> msg,
      Ptr<task_struct> target, long type, int mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_msg_queue_msgsnd(Ptr<kern_ipc_perm> msq, Ptr<msg_msg> msg,
      int msqflg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_net_peersid_resolve(@Unsigned int nlbl_sid, @Unsigned int nlbl_type,
      @Unsigned int xfrm_sid, Ptr<java.lang. @Unsigned Integer> peer_sid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_netif_sid((const u8 *)$arg1, $arg2)")
  public static int security_netif_sid(String name, Ptr<java.lang. @Unsigned Integer> if_sid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_netlbl_secattr_to_sid(Ptr<netlbl_lsm_secattr> secattr,
      Ptr<java.lang. @Unsigned Integer> sid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_netlbl_sid_to_secattr(@Unsigned int sid,
      Ptr<netlbl_lsm_secattr> secattr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_netlink_send(Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_node_sid($arg1, (const void *)$arg2, $arg3, $arg4)")
  public static int security_node_sid(@Unsigned short domain, Ptr<?> addrp, @Unsigned int addrlen,
      Ptr<java.lang. @Unsigned Integer> out_sid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_overwrite(Ptr<nvdimm> nvdimm, @Unsigned int keyid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_path_chmod((const struct path *)$arg1, $arg2)")
  public static int security_path_chmod(Ptr<path> path,
      @Unsigned @OriginalName("umode_t") short mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_path_chown((const struct path *)$arg1, $arg2, $arg3)")
  public static int security_path_chown(Ptr<path> path, kuid_t uid, kgid_t gid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_path_chroot((const struct path *)$arg1)")
  public static int security_path_chroot(Ptr<path> path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_path_link($arg1, (const struct path *)$arg2, $arg3)")
  public static int security_path_link(Ptr<dentry> old_dentry, Ptr<path> new_dir,
      Ptr<dentry> new_dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_path_mkdir((const struct path *)$arg1, $arg2, $arg3)")
  public static int security_path_mkdir(Ptr<path> dir, Ptr<dentry> dentry,
      @Unsigned @OriginalName("umode_t") short mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_path_mknod((const struct path *)$arg1, $arg2, $arg3, $arg4)")
  public static int security_path_mknod(Ptr<path> dir, Ptr<dentry> dentry,
      @Unsigned @OriginalName("umode_t") short mode, @Unsigned int dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_path_notify((const struct path *)$arg1, $arg2, $arg3)")
  public static int security_path_notify(Ptr<path> path, @Unsigned long mask,
      @Unsigned int obj_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_path_post_mknod(Ptr<mnt_idmap> idmap, Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_path_rename((const struct path *)$arg1, $arg2, (const struct path *)$arg3, $arg4, $arg5)")
  public static int security_path_rename(Ptr<path> old_dir, Ptr<dentry> old_dentry,
      Ptr<path> new_dir, Ptr<dentry> new_dentry, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_path_rmdir((const struct path *)$arg1, $arg2)")
  public static int security_path_rmdir(Ptr<path> dir, Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_path_symlink((const struct path *)$arg1, $arg2, (const u8 *)$arg3)")
  public static int security_path_symlink(Ptr<path> dir, Ptr<dentry> dentry, String old_name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_path_truncate((const struct path *)$arg1)")
  public static int security_path_truncate(Ptr<path> path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_path_unlink((const struct path *)$arg1, $arg2)")
  public static int security_path_unlink(Ptr<path> dir, Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_perf_event_alloc(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_perf_event_free(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_perf_event_open(int type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_perf_event_read(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_perf_event_write(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_policycap_supported(@Unsigned int req_cap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_port_sid(char protocol, @Unsigned short port,
      Ptr<java.lang. @Unsigned Integer> out_sid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_post_notification((const struct cred *)$arg1, (const struct cred *)$arg2, $arg3)")
  public static int security_post_notification(Ptr<cred> w_cred, Ptr<cred> cred,
      Ptr<watch_notification> n) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_prepare_creds($arg1, (const struct cred *)$arg2, $arg3)")
  public static int security_prepare_creds(Ptr<cred> _new, Ptr<cred> old,
      @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_ptrace_access_check(Ptr<task_struct> child, @Unsigned int mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_ptrace_traceme(Ptr<task_struct> parent) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_quota_on(Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_quotactl($arg1, $arg2, $arg3, (const struct super_block *)$arg4)")
  public static int security_quotactl(int cmds, int type, int id, Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_read_policy(Ptr<Ptr<?>> data, Ptr<java.lang. @Unsigned Long> len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_read_state_kernel(Ptr<Ptr<?>> data,
      Ptr<java.lang. @Unsigned Long> len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_release_secctx(Ptr<lsm_context> cp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_req_classify_flow((const struct request_sock *)$arg1, $arg2)")
  public static void security_req_classify_flow(Ptr<request_sock> req, Ptr<flowi_common> flic) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_sb_alloc(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_sb_clone_mnt_opts((const struct super_block *)$arg1, $arg2, $arg3, $arg4)")
  public static int security_sb_clone_mnt_opts(Ptr<super_block> oldsb, Ptr<super_block> newsb,
      @Unsigned long kern_flags, Ptr<java.lang. @Unsigned Long> set_kern_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_sb_delete(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_sb_eat_lsm_opts(String options, Ptr<Ptr<?>> mnt_opts) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_sb_free(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_sb_kern_mount((const struct super_block *)$arg1)")
  public static int security_sb_kern_mount(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_sb_mnt_opts_compat(Ptr<super_block> sb, Ptr<?> mnt_opts) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_sb_mount((const u8 *)$arg1, (const struct path *)$arg2, (const u8 *)$arg3, $arg4, $arg5)")
  public static int security_sb_mount(String dev_name, Ptr<path> path, String type,
      @Unsigned long flags, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_sb_pivotroot((const struct path *)$arg1, (const struct path *)$arg2)")
  public static int security_sb_pivotroot(Ptr<path> old_path, Ptr<path> new_path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_sb_remount(Ptr<super_block> sb, Ptr<?> mnt_opts) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_sb_set_mnt_opts(Ptr<super_block> sb, Ptr<?> mnt_opts,
      @Unsigned long kern_flags, Ptr<java.lang. @Unsigned Long> set_kern_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_sb_show_options(Ptr<seq_file> m, Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_sb_statfs(Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_sb_umount(Ptr<vfsmount> mnt, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_sctp_assoc_established(Ptr<sctp_association> asoc, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_sctp_assoc_request(Ptr<sctp_association> asoc, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_sctp_bind_connect(Ptr<sock> sk, int optname, Ptr<sockaddr> address,
      int addrlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_sctp_sk_clone(Ptr<sctp_association> asoc, Ptr<sock> sk,
      Ptr<sock> newsk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_secctx_to_secid((const u8 *)$arg1, $arg2, $arg3)")
  public static int security_secctx_to_secid(String secdata, @Unsigned int seclen,
      Ptr<java.lang. @Unsigned Integer> secid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_secid_to_secctx(@Unsigned int secid, Ptr<lsm_context> cp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_secmark_refcount_dec() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_secmark_refcount_inc() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_secmark_relabel_packet(@Unsigned int secid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_sem_alloc(Ptr<kern_ipc_perm> sma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_sem_associate(Ptr<kern_ipc_perm> sma, int semflg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_sem_free(Ptr<kern_ipc_perm> sma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_sem_semctl(Ptr<kern_ipc_perm> sma, int cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_sem_semop(Ptr<kern_ipc_perm> sma, Ptr<sembuf> sops,
      @Unsigned int nsops, int alter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_set_bools($arg1, (const int *)$arg2)")
  public static int security_set_bools(@Unsigned int len, Ptr<java.lang.Integer> values) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_setprocattr($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static int security_setprocattr(int lsmid, String name, Ptr<?> value,
      @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_setselfattr(@Unsigned int attr, Ptr<lsm_ctx> uctx, @Unsigned int size,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_settime64((const struct timespec64 *)$arg1, (const struct timezone *)$arg2)")
  public static int security_settime64(Ptr<timespec64> ts, Ptr<timezone> tz) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_shm_alloc(Ptr<kern_ipc_perm> shp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_shm_associate(Ptr<kern_ipc_perm> shp, int shmflg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_shm_free(Ptr<kern_ipc_perm> shp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_shm_shmat(Ptr<kern_ipc_perm> shp, String shmaddr, int shmflg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_shm_shmctl(Ptr<kern_ipc_perm> shp, int cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long security_show(Ptr<device> dev,
      Ptr<device_attribute> attr, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_sid_mls_copy(@Unsigned int sid, @Unsigned int mls_sid,
      Ptr<java.lang. @Unsigned Integer> new_sid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_sid_to_context(@Unsigned int sid, Ptr<String> scontext,
      Ptr<java.lang. @Unsigned Integer> scontext_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_sid_to_context_core(@Unsigned int sid, Ptr<String> scontext,
      Ptr<java.lang. @Unsigned Integer> scontext_len, int force, int only_invalid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_sid_to_context_force(@Unsigned int sid, Ptr<String> scontext,
      Ptr<java.lang. @Unsigned Integer> scontext_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_sid_to_context_inval(@Unsigned int sid, Ptr<String> scontext,
      Ptr<java.lang. @Unsigned Integer> scontext_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_sidtab_hash_stats(String page) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_sk_alloc(Ptr<sock> sk, int family,
      @Unsigned @OriginalName("gfp_t") int priority) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_sk_classify_flow((const struct sock *)$arg1, $arg2)")
  public static void security_sk_classify_flow(Ptr<sock> sk, Ptr<flowi_common> flic) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_sk_clone((const struct sock *)$arg1, $arg2)")
  public static void security_sk_clone(Ptr<sock> sk, Ptr<sock> newsk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_sk_free(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_skb_classify_flow(Ptr<sk_buff> skb, Ptr<flowi_common> flic) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_sock_graft(Ptr<sock> sk, Ptr<socket> parent) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_sock_rcv_skb(Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_socket_accept(Ptr<socket> sock, Ptr<socket> newsock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_socket_bind(Ptr<socket> sock, Ptr<sockaddr> address, int addrlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_socket_connect(Ptr<socket> sock, Ptr<sockaddr> address, int addrlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_socket_create(int family, int type, int protocol, int kern) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_socket_getpeername(Ptr<socket> sock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_socket_getpeersec_dgram(Ptr<socket> sock, Ptr<sk_buff> skb,
      Ptr<java.lang. @Unsigned Integer> secid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_socket_getpeersec_stream(Ptr<socket> sock, sockptr_t optval,
      sockptr_t optlen, @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_socket_getsockname(Ptr<socket> sock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_socket_getsockopt(Ptr<socket> sock, int level, int optname) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_socket_listen(Ptr<socket> sock, int backlog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_socket_post_create(Ptr<socket> sock, int family, int type,
      int protocol, int kern) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_socket_recvmsg(Ptr<socket> sock, Ptr<msghdr> msg, int size,
      int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_socket_sendmsg(Ptr<socket> sock, Ptr<msghdr> msg, int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_socket_setsockopt(Ptr<socket> sock, int level, int optname) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_socket_shutdown(Ptr<socket> sock, int how) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_socket_socketpair(Ptr<socket> socka, Ptr<socket> sockb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_store($arg1, $arg2, (const u8 *)$arg3, $arg4)")
  public static @OriginalName("ssize_t") long security_store(Ptr<device> dev,
      Ptr<device_attribute> attr, String buf, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_syslog(int type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_task_alloc(Ptr<task_struct> task, @Unsigned long clone_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_task_fix_setgid($arg1, (const struct cred *)$arg2, $arg3)")
  public static int security_task_fix_setgid(Ptr<cred> _new, Ptr<cred> old, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_task_fix_setgroups($arg1, (const struct cred *)$arg2)")
  public static int security_task_fix_setgroups(Ptr<cred> _new, Ptr<cred> old) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_task_fix_setuid($arg1, (const struct cred *)$arg2, $arg3)")
  public static int security_task_fix_setuid(Ptr<cred> _new, Ptr<cred> old, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_task_free(Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_task_getioprio(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_task_getlsmprop_obj(Ptr<task_struct> p, Ptr<lsm_prop> prop) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_task_getpgid(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_task_getscheduler(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_task_getsid(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_task_kill($arg1, $arg2, $arg3, (const struct cred *)$arg4)")
  public static int security_task_kill(Ptr<task_struct> p, Ptr<kernel_siginfo> info, int sig,
      Ptr<cred> cred) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_task_movememory(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_task_prctl(int option, @Unsigned long arg2, @Unsigned long arg3,
      @Unsigned long arg4, @Unsigned long arg5) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_task_prlimit((const struct cred *)$arg1, (const struct cred *)$arg2, $arg3)")
  public static int security_task_prlimit(Ptr<cred> cred, Ptr<cred> tcred, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_task_setioprio(Ptr<task_struct> p, int ioprio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_task_setnice(Ptr<task_struct> p, int nice) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_task_setpgid(Ptr<task_struct> p, @OriginalName("pid_t") int pgid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_task_setrlimit(Ptr<task_struct> p, @Unsigned int resource,
      Ptr<rlimit> new_rlim) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_task_setscheduler(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_task_to_inode(Ptr<task_struct> p, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_transfer_creds($arg1, (const struct cred *)$arg2)")
  public static void security_transfer_creds(Ptr<cred> _new, Ptr<cred> old) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_transition_sid($arg1, $arg2, $arg3, (const struct qstr *)$arg4, $arg5)")
  public static int security_transition_sid(@Unsigned int ssid, @Unsigned int tsid,
      @Unsigned short tclass, Ptr<qstr> qstr, Ptr<java.lang. @Unsigned Integer> out_sid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_transition_sid_user($arg1, $arg2, $arg3, (const u8 *)$arg4, $arg5)")
  public static int security_transition_sid_user(@Unsigned int ssid, @Unsigned int tsid,
      @Unsigned short tclass, String objname, Ptr<java.lang. @Unsigned Integer> out_sid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_tun_dev_alloc_security(Ptr<Ptr<?>> security) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_tun_dev_attach(Ptr<sock> sk, Ptr<?> security) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_tun_dev_attach_queue(Ptr<?> security) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_tun_dev_create() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_tun_dev_free_security(Ptr<?> security) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_tun_dev_open(Ptr<?> security) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_unix_may_send(Ptr<socket> sock, Ptr<socket> other) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_unix_stream_connect(Ptr<sock> sock, Ptr<sock> other, Ptr<sock> newsk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_update(Ptr<nvdimm> nvdimm, @Unsigned int keyid,
      @Unsigned int new_keyid, nvdimm_passphrase_type pass_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_uring_allowed() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_uring_cmd(Ptr<io_uring_cmd> ioucmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_uring_override_creds((const struct cred *)$arg1)")
  public static int security_uring_override_creds(Ptr<cred> _new) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_uring_sqpoll() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_validate_transition(@Unsigned int oldsid, @Unsigned int newsid,
      @Unsigned int tasksid, @Unsigned short orig_tclass) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_validate_transition_user(@Unsigned int oldsid, @Unsigned int newsid,
      @Unsigned int tasksid, @Unsigned short tclass) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_vm_enough_memory_mm(Ptr<mm_struct> mm, long pages) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_watch_key(Ptr<key> key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_xfrm_decode_session(Ptr<sk_buff> skb,
      Ptr<java.lang. @Unsigned Integer> secid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_xfrm_policy_alloc(Ptr<Ptr<xfrm_sec_ctx>> ctxp,
      Ptr<xfrm_user_sec_ctx> sec_ctx, @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_xfrm_policy_clone(Ptr<xfrm_sec_ctx> old_ctx,
      Ptr<Ptr<xfrm_sec_ctx>> new_ctxp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_xfrm_policy_delete(Ptr<xfrm_sec_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_xfrm_policy_free(Ptr<xfrm_sec_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_xfrm_policy_lookup(Ptr<xfrm_sec_ctx> ctx, @Unsigned int fl_secid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_xfrm_state_alloc(Ptr<xfrm_state> x, Ptr<xfrm_user_sec_ctx> sec_ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_xfrm_state_alloc_acquire(Ptr<xfrm_state> x, Ptr<xfrm_sec_ctx> polsec,
      @Unsigned int secid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int security_xfrm_state_delete(Ptr<xfrm_state> x) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void security_xfrm_state_free(Ptr<xfrm_state> x) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("security_xfrm_state_pol_flow_match($arg1, $arg2, (const struct flowi_common *)$arg3)")
  public static int security_xfrm_state_pol_flow_match(Ptr<xfrm_state> x, Ptr<xfrm_policy> xp,
      Ptr<flowi_common> flic) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union security_list_options"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class security_list_options extends Union {
    public Ptr<?> binder_set_context_mgr;

    public Ptr<?> binder_transaction;

    public Ptr<?> binder_transfer_binder;

    public Ptr<?> binder_transfer_file;

    public Ptr<?> ptrace_access_check;

    public Ptr<?> ptrace_traceme;

    public Ptr<?> capget;

    public Ptr<?> capset;

    public Ptr<?> capable;

    public Ptr<?> quotactl;

    public Ptr<?> quota_on;

    public Ptr<?> syslog;

    public Ptr<?> settime;

    public Ptr<?> vm_enough_memory;

    public Ptr<?> bprm_creds_for_exec;

    public Ptr<?> bprm_creds_from_file;

    public Ptr<?> bprm_check_security;

    public Ptr<?> bprm_committing_creds;

    public Ptr<?> bprm_committed_creds;

    public Ptr<?> fs_context_submount;

    public Ptr<?> fs_context_dup;

    public Ptr<?> fs_context_parse_param;

    public Ptr<?> sb_alloc_security;

    public Ptr<?> sb_delete;

    public Ptr<?> sb_free_security;

    public Ptr<?> sb_free_mnt_opts;

    public Ptr<?> sb_eat_lsm_opts;

    public Ptr<?> sb_mnt_opts_compat;

    public Ptr<?> sb_remount;

    public Ptr<?> sb_kern_mount;

    public Ptr<?> sb_show_options;

    public Ptr<?> sb_statfs;

    public Ptr<?> sb_mount;

    public Ptr<?> sb_umount;

    public Ptr<?> sb_pivotroot;

    public Ptr<?> sb_set_mnt_opts;

    public Ptr<?> sb_clone_mnt_opts;

    public Ptr<?> move_mount;

    public Ptr<?> dentry_init_security;

    public Ptr<?> dentry_create_files_as;

    public Ptr<?> path_unlink;

    public Ptr<?> path_mkdir;

    public Ptr<?> path_rmdir;

    public Ptr<?> path_mknod;

    public Ptr<?> path_post_mknod;

    public Ptr<?> path_truncate;

    public Ptr<?> path_symlink;

    public Ptr<?> path_link;

    public Ptr<?> path_rename;

    public Ptr<?> path_chmod;

    public Ptr<?> path_chown;

    public Ptr<?> path_chroot;

    public Ptr<?> path_notify;

    public Ptr<?> inode_alloc_security;

    public Ptr<?> inode_free_security;

    public Ptr<?> inode_free_security_rcu;

    public Ptr<?> inode_init_security;

    public Ptr<?> inode_init_security_anon;

    public Ptr<?> inode_create;

    public Ptr<?> inode_post_create_tmpfile;

    public Ptr<?> inode_link;

    public Ptr<?> inode_unlink;

    public Ptr<?> inode_symlink;

    public Ptr<?> inode_mkdir;

    public Ptr<?> inode_rmdir;

    public Ptr<?> inode_mknod;

    public Ptr<?> inode_rename;

    public Ptr<?> inode_readlink;

    public Ptr<?> inode_follow_link;

    public Ptr<?> inode_permission;

    public Ptr<?> inode_setattr;

    public Ptr<?> inode_post_setattr;

    public Ptr<?> inode_getattr;

    public Ptr<?> inode_xattr_skipcap;

    public Ptr<?> inode_setxattr;

    public Ptr<?> inode_post_setxattr;

    public Ptr<?> inode_getxattr;

    public Ptr<?> inode_listxattr;

    public Ptr<?> inode_removexattr;

    public Ptr<?> inode_post_removexattr;

    public Ptr<?> inode_file_setattr;

    public Ptr<?> inode_file_getattr;

    public Ptr<?> inode_set_acl;

    public Ptr<?> inode_post_set_acl;

    public Ptr<?> inode_get_acl;

    public Ptr<?> inode_remove_acl;

    public Ptr<?> inode_post_remove_acl;

    public Ptr<?> inode_need_killpriv;

    public Ptr<?> inode_killpriv;

    public Ptr<?> inode_getsecurity;

    public Ptr<?> inode_setsecurity;

    public Ptr<?> inode_listsecurity;

    public Ptr<?> inode_getlsmprop;

    public Ptr<?> inode_copy_up;

    public Ptr<?> inode_copy_up_xattr;

    public Ptr<?> inode_setintegrity;

    public Ptr<?> kernfs_init_security;

    public Ptr<?> file_permission;

    public Ptr<?> file_alloc_security;

    public Ptr<?> file_release;

    public Ptr<?> file_free_security;

    public Ptr<?> file_ioctl;

    public Ptr<?> file_ioctl_compat;

    public Ptr<?> mmap_addr;

    public Ptr<?> mmap_file;

    public Ptr<?> file_mprotect;

    public Ptr<?> file_lock;

    public Ptr<?> file_fcntl;

    public Ptr<?> file_set_fowner;

    public Ptr<?> file_send_sigiotask;

    public Ptr<?> file_receive;

    public Ptr<?> file_open;

    public Ptr<?> file_post_open;

    public Ptr<?> file_truncate;

    public Ptr<?> task_alloc;

    public Ptr<?> task_free;

    public Ptr<?> cred_alloc_blank;

    public Ptr<?> cred_free;

    public Ptr<?> cred_prepare;

    public Ptr<?> cred_transfer;

    public Ptr<?> cred_getsecid;

    public Ptr<?> cred_getlsmprop;

    public Ptr<?> kernel_act_as;

    public Ptr<?> kernel_create_files_as;

    public Ptr<?> kernel_module_request;

    public Ptr<?> kernel_load_data;

    public Ptr<?> kernel_post_load_data;

    public Ptr<?> kernel_read_file;

    public Ptr<?> kernel_post_read_file;

    public Ptr<?> task_fix_setuid;

    public Ptr<?> task_fix_setgid;

    public Ptr<?> task_fix_setgroups;

    public Ptr<?> task_setpgid;

    public Ptr<?> task_getpgid;

    public Ptr<?> task_getsid;

    public Ptr<?> current_getlsmprop_subj;

    public Ptr<?> task_getlsmprop_obj;

    public Ptr<?> task_setnice;

    public Ptr<?> task_setioprio;

    public Ptr<?> task_getioprio;

    public Ptr<?> task_prlimit;

    public Ptr<?> task_setrlimit;

    public Ptr<?> task_setscheduler;

    public Ptr<?> task_getscheduler;

    public Ptr<?> task_movememory;

    public Ptr<?> task_kill;

    public Ptr<?> task_prctl;

    public Ptr<?> task_to_inode;

    public Ptr<?> userns_create;

    public Ptr<?> ipc_permission;

    public Ptr<?> ipc_getlsmprop;

    public Ptr<?> msg_msg_alloc_security;

    public Ptr<?> msg_msg_free_security;

    public Ptr<?> msg_queue_alloc_security;

    public Ptr<?> msg_queue_free_security;

    public Ptr<?> msg_queue_associate;

    public Ptr<?> msg_queue_msgctl;

    public Ptr<?> msg_queue_msgsnd;

    public Ptr<?> msg_queue_msgrcv;

    public Ptr<?> shm_alloc_security;

    public Ptr<?> shm_free_security;

    public Ptr<?> shm_associate;

    public Ptr<?> shm_shmctl;

    public Ptr<?> shm_shmat;

    public Ptr<?> sem_alloc_security;

    public Ptr<?> sem_free_security;

    public Ptr<?> sem_associate;

    public Ptr<?> sem_semctl;

    public Ptr<?> sem_semop;

    public Ptr<?> netlink_send;

    public Ptr<?> d_instantiate;

    public Ptr<?> getselfattr;

    public Ptr<?> setselfattr;

    public Ptr<?> getprocattr;

    public Ptr<?> setprocattr;

    public Ptr<?> ismaclabel;

    public Ptr<?> secid_to_secctx;

    public Ptr<?> lsmprop_to_secctx;

    public Ptr<?> secctx_to_secid;

    public Ptr<?> release_secctx;

    public Ptr<?> inode_invalidate_secctx;

    public Ptr<?> inode_notifysecctx;

    public Ptr<?> inode_setsecctx;

    public Ptr<?> inode_getsecctx;

    public Ptr<?> post_notification;

    public Ptr<?> watch_key;

    public Ptr<?> unix_stream_connect;

    public Ptr<?> unix_may_send;

    public Ptr<?> socket_create;

    public Ptr<?> socket_post_create;

    public Ptr<?> socket_socketpair;

    public Ptr<?> socket_bind;

    public Ptr<?> socket_connect;

    public Ptr<?> socket_listen;

    public Ptr<?> socket_accept;

    public Ptr<?> socket_sendmsg;

    public Ptr<?> socket_recvmsg;

    public Ptr<?> socket_getsockname;

    public Ptr<?> socket_getpeername;

    public Ptr<?> socket_getsockopt;

    public Ptr<?> socket_setsockopt;

    public Ptr<?> socket_shutdown;

    public Ptr<?> socket_sock_rcv_skb;

    public Ptr<?> socket_getpeersec_stream;

    public Ptr<?> socket_getpeersec_dgram;

    public Ptr<?> sk_alloc_security;

    public Ptr<?> sk_free_security;

    public Ptr<?> sk_clone_security;

    public Ptr<?> sk_getsecid;

    public Ptr<?> sock_graft;

    public Ptr<?> inet_conn_request;

    public Ptr<?> inet_csk_clone;

    public Ptr<?> inet_conn_established;

    public Ptr<?> secmark_relabel_packet;

    public Ptr<?> secmark_refcount_inc;

    public Ptr<?> secmark_refcount_dec;

    public Ptr<?> req_classify_flow;

    public Ptr<?> tun_dev_alloc_security;

    public Ptr<?> tun_dev_create;

    public Ptr<?> tun_dev_attach_queue;

    public Ptr<?> tun_dev_attach;

    public Ptr<?> tun_dev_open;

    public Ptr<?> sctp_assoc_request;

    public Ptr<?> sctp_bind_connect;

    public Ptr<?> sctp_sk_clone;

    public Ptr<?> sctp_assoc_established;

    public Ptr<?> mptcp_add_subflow;

    public Ptr<?> ib_pkey_access;

    public Ptr<?> ib_endport_manage_subnet;

    public Ptr<?> ib_alloc_security;

    public Ptr<?> xfrm_policy_alloc_security;

    public Ptr<?> xfrm_policy_clone_security;

    public Ptr<?> xfrm_policy_free_security;

    public Ptr<?> xfrm_policy_delete_security;

    public Ptr<?> xfrm_state_alloc;

    public Ptr<?> xfrm_state_alloc_acquire;

    public Ptr<?> xfrm_state_free_security;

    public Ptr<?> xfrm_state_delete_security;

    public Ptr<?> xfrm_policy_lookup;

    public Ptr<?> xfrm_state_pol_flow_match;

    public Ptr<?> xfrm_decode_session;

    public Ptr<?> key_alloc;

    public Ptr<?> key_permission;

    public Ptr<?> key_getsecurity;

    public Ptr<?> key_post_create_or_update;

    public Ptr<?> audit_rule_init;

    public Ptr<?> audit_rule_known;

    public Ptr<?> audit_rule_match;

    public Ptr<?> audit_rule_free;

    public Ptr<?> bpf;

    public Ptr<?> bpf_map;

    public Ptr<?> bpf_prog;

    public Ptr<?> bpf_map_create;

    public Ptr<?> bpf_map_free;

    public Ptr<?> bpf_prog_load;

    public Ptr<?> bpf_prog_free;

    public Ptr<?> bpf_token_create;

    public Ptr<?> bpf_token_free;

    public Ptr<?> bpf_token_cmd;

    public Ptr<?> bpf_token_capable;

    public Ptr<?> locked_down;

    public Ptr<?> lock_kernel_down;

    public Ptr<?> perf_event_open;

    public Ptr<?> perf_event_alloc;

    public Ptr<?> perf_event_read;

    public Ptr<?> perf_event_write;

    public Ptr<?> uring_override_creds;

    public Ptr<?> uring_sqpoll;

    public Ptr<?> uring_cmd;

    public Ptr<?> uring_allowed;

    public Ptr<?> initramfs_populated;

    public Ptr<?> bdev_alloc_security;

    public Ptr<?> bdev_free_security;

    public Ptr<?> bdev_setintegrity;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct security_hook_heads"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class security_hook_heads extends Struct {
    public hlist_head binder_set_context_mgr;

    public hlist_head binder_transaction;

    public hlist_head binder_transfer_binder;

    public hlist_head binder_transfer_file;

    public hlist_head ptrace_access_check;

    public hlist_head ptrace_traceme;

    public hlist_head capget;

    public hlist_head capset;

    public hlist_head capable;

    public hlist_head quotactl;

    public hlist_head quota_on;

    public hlist_head syslog;

    public hlist_head settime;

    public hlist_head vm_enough_memory;

    public hlist_head bprm_creds_for_exec;

    public hlist_head bprm_creds_from_file;

    public hlist_head bprm_check_security;

    public hlist_head bprm_committing_creds;

    public hlist_head bprm_committed_creds;

    public hlist_head fs_context_submount;

    public hlist_head fs_context_dup;

    public hlist_head fs_context_parse_param;

    public hlist_head sb_alloc_security;

    public hlist_head sb_delete;

    public hlist_head sb_free_security;

    public hlist_head sb_free_mnt_opts;

    public hlist_head sb_eat_lsm_opts;

    public hlist_head sb_mnt_opts_compat;

    public hlist_head sb_remount;

    public hlist_head sb_kern_mount;

    public hlist_head sb_show_options;

    public hlist_head sb_statfs;

    public hlist_head sb_mount;

    public hlist_head sb_umount;

    public hlist_head sb_pivotroot;

    public hlist_head sb_set_mnt_opts;

    public hlist_head sb_clone_mnt_opts;

    public hlist_head move_mount;

    public hlist_head dentry_init_security;

    public hlist_head dentry_create_files_as;

    public hlist_head path_unlink;

    public hlist_head path_mkdir;

    public hlist_head path_rmdir;

    public hlist_head path_mknod;

    public hlist_head path_post_mknod;

    public hlist_head path_truncate;

    public hlist_head path_symlink;

    public hlist_head path_link;

    public hlist_head path_rename;

    public hlist_head path_chmod;

    public hlist_head path_chown;

    public hlist_head path_chroot;

    public hlist_head path_notify;

    public hlist_head inode_alloc_security;

    public hlist_head inode_free_security;

    public hlist_head inode_free_security_rcu;

    public hlist_head inode_init_security;

    public hlist_head inode_init_security_anon;

    public hlist_head inode_create;

    public hlist_head inode_post_create_tmpfile;

    public hlist_head inode_link;

    public hlist_head inode_unlink;

    public hlist_head inode_symlink;

    public hlist_head inode_mkdir;

    public hlist_head inode_rmdir;

    public hlist_head inode_mknod;

    public hlist_head inode_rename;

    public hlist_head inode_readlink;

    public hlist_head inode_follow_link;

    public hlist_head inode_permission;

    public hlist_head inode_setattr;

    public hlist_head inode_post_setattr;

    public hlist_head inode_getattr;

    public hlist_head inode_xattr_skipcap;

    public hlist_head inode_setxattr;

    public hlist_head inode_post_setxattr;

    public hlist_head inode_getxattr;

    public hlist_head inode_listxattr;

    public hlist_head inode_removexattr;

    public hlist_head inode_post_removexattr;

    public hlist_head inode_file_setattr;

    public hlist_head inode_file_getattr;

    public hlist_head inode_set_acl;

    public hlist_head inode_post_set_acl;

    public hlist_head inode_get_acl;

    public hlist_head inode_remove_acl;

    public hlist_head inode_post_remove_acl;

    public hlist_head inode_need_killpriv;

    public hlist_head inode_killpriv;

    public hlist_head inode_getsecurity;

    public hlist_head inode_setsecurity;

    public hlist_head inode_listsecurity;

    public hlist_head inode_getlsmprop;

    public hlist_head inode_copy_up;

    public hlist_head inode_copy_up_xattr;

    public hlist_head inode_setintegrity;

    public hlist_head kernfs_init_security;

    public hlist_head file_permission;

    public hlist_head file_alloc_security;

    public hlist_head file_release;

    public hlist_head file_free_security;

    public hlist_head file_ioctl;

    public hlist_head file_ioctl_compat;

    public hlist_head mmap_addr;

    public hlist_head mmap_file;

    public hlist_head file_mprotect;

    public hlist_head file_lock;

    public hlist_head file_fcntl;

    public hlist_head file_set_fowner;

    public hlist_head file_send_sigiotask;

    public hlist_head file_receive;

    public hlist_head file_open;

    public hlist_head file_post_open;

    public hlist_head file_truncate;

    public hlist_head task_alloc;

    public hlist_head task_free;

    public hlist_head cred_alloc_blank;

    public hlist_head cred_free;

    public hlist_head cred_prepare;

    public hlist_head cred_transfer;

    public hlist_head cred_getsecid;

    public hlist_head cred_getlsmprop;

    public hlist_head kernel_act_as;

    public hlist_head kernel_create_files_as;

    public hlist_head kernel_module_request;

    public hlist_head kernel_load_data;

    public hlist_head kernel_post_load_data;

    public hlist_head kernel_read_file;

    public hlist_head kernel_post_read_file;

    public hlist_head task_fix_setuid;

    public hlist_head task_fix_setgid;

    public hlist_head task_fix_setgroups;

    public hlist_head task_setpgid;

    public hlist_head task_getpgid;

    public hlist_head task_getsid;

    public hlist_head current_getlsmprop_subj;

    public hlist_head task_getlsmprop_obj;

    public hlist_head task_setnice;

    public hlist_head task_setioprio;

    public hlist_head task_getioprio;

    public hlist_head task_prlimit;

    public hlist_head task_setrlimit;

    public hlist_head task_setscheduler;

    public hlist_head task_getscheduler;

    public hlist_head task_movememory;

    public hlist_head task_kill;

    public hlist_head task_prctl;

    public hlist_head task_to_inode;

    public hlist_head userns_create;

    public hlist_head ipc_permission;

    public hlist_head ipc_getlsmprop;

    public hlist_head msg_msg_alloc_security;

    public hlist_head msg_msg_free_security;

    public hlist_head msg_queue_alloc_security;

    public hlist_head msg_queue_free_security;

    public hlist_head msg_queue_associate;

    public hlist_head msg_queue_msgctl;

    public hlist_head msg_queue_msgsnd;

    public hlist_head msg_queue_msgrcv;

    public hlist_head shm_alloc_security;

    public hlist_head shm_free_security;

    public hlist_head shm_associate;

    public hlist_head shm_shmctl;

    public hlist_head shm_shmat;

    public hlist_head sem_alloc_security;

    public hlist_head sem_free_security;

    public hlist_head sem_associate;

    public hlist_head sem_semctl;

    public hlist_head sem_semop;

    public hlist_head netlink_send;

    public hlist_head d_instantiate;

    public hlist_head getselfattr;

    public hlist_head setselfattr;

    public hlist_head getprocattr;

    public hlist_head setprocattr;

    public hlist_head ismaclabel;

    public hlist_head secid_to_secctx;

    public hlist_head lsmprop_to_secctx;

    public hlist_head secctx_to_secid;

    public hlist_head release_secctx;

    public hlist_head inode_invalidate_secctx;

    public hlist_head inode_notifysecctx;

    public hlist_head inode_setsecctx;

    public hlist_head inode_getsecctx;

    public hlist_head post_notification;

    public hlist_head watch_key;

    public hlist_head unix_stream_connect;

    public hlist_head unix_may_send;

    public hlist_head socket_create;

    public hlist_head socket_post_create;

    public hlist_head socket_socketpair;

    public hlist_head socket_bind;

    public hlist_head socket_connect;

    public hlist_head socket_listen;

    public hlist_head socket_accept;

    public hlist_head socket_sendmsg;

    public hlist_head socket_recvmsg;

    public hlist_head socket_getsockname;

    public hlist_head socket_getpeername;

    public hlist_head socket_getsockopt;

    public hlist_head socket_setsockopt;

    public hlist_head socket_shutdown;

    public hlist_head socket_sock_rcv_skb;

    public hlist_head socket_getpeersec_stream;

    public hlist_head socket_getpeersec_dgram;

    public hlist_head sk_alloc_security;

    public hlist_head sk_free_security;

    public hlist_head sk_clone_security;

    public hlist_head sk_getsecid;

    public hlist_head sock_graft;

    public hlist_head inet_conn_request;

    public hlist_head inet_csk_clone;

    public hlist_head inet_conn_established;

    public hlist_head secmark_relabel_packet;

    public hlist_head secmark_refcount_inc;

    public hlist_head secmark_refcount_dec;

    public hlist_head req_classify_flow;

    public hlist_head tun_dev_alloc_security;

    public hlist_head tun_dev_create;

    public hlist_head tun_dev_attach_queue;

    public hlist_head tun_dev_attach;

    public hlist_head tun_dev_open;

    public hlist_head sctp_assoc_request;

    public hlist_head sctp_bind_connect;

    public hlist_head sctp_sk_clone;

    public hlist_head sctp_assoc_established;

    public hlist_head mptcp_add_subflow;

    public hlist_head ib_pkey_access;

    public hlist_head ib_endport_manage_subnet;

    public hlist_head ib_alloc_security;

    public hlist_head xfrm_policy_alloc_security;

    public hlist_head xfrm_policy_clone_security;

    public hlist_head xfrm_policy_free_security;

    public hlist_head xfrm_policy_delete_security;

    public hlist_head xfrm_state_alloc;

    public hlist_head xfrm_state_alloc_acquire;

    public hlist_head xfrm_state_free_security;

    public hlist_head xfrm_state_delete_security;

    public hlist_head xfrm_policy_lookup;

    public hlist_head xfrm_state_pol_flow_match;

    public hlist_head xfrm_decode_session;

    public hlist_head key_alloc;

    public hlist_head key_permission;

    public hlist_head key_getsecurity;

    public hlist_head key_post_create_or_update;

    public hlist_head audit_rule_init;

    public hlist_head audit_rule_known;

    public hlist_head audit_rule_match;

    public hlist_head audit_rule_free;

    public hlist_head bpf;

    public hlist_head bpf_map;

    public hlist_head bpf_prog;

    public hlist_head bpf_map_create;

    public hlist_head bpf_map_free;

    public hlist_head bpf_prog_load;

    public hlist_head bpf_prog_free;

    public hlist_head bpf_token_create;

    public hlist_head bpf_token_free;

    public hlist_head bpf_token_cmd;

    public hlist_head bpf_token_capable;

    public hlist_head locked_down;

    public hlist_head lock_kernel_down;

    public hlist_head perf_event_open;

    public hlist_head perf_event_alloc;

    public hlist_head perf_event_read;

    public hlist_head perf_event_write;

    public hlist_head uring_override_creds;

    public hlist_head uring_sqpoll;

    public hlist_head uring_cmd;

    public hlist_head uring_allowed;

    public hlist_head initramfs_populated;

    public hlist_head bdev_alloc_security;

    public hlist_head bdev_free_security;

    public hlist_head bdev_setintegrity;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct security_hook_list"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class security_hook_list extends Struct {
    public hlist_node list;

    public Ptr<hlist_head> head;

    public security_list_options hook;

    public Ptr<lsm_id> lsmid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct security_class_mapping"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class security_class_mapping extends Struct {
    public String name;

    public String @Size(33) [] perms;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum security_cmd_enabled_bits"
  )
  public enum security_cmd_enabled_bits implements Enum<security_cmd_enabled_bits>, TypedEnum<security_cmd_enabled_bits, java.lang. @Unsigned Integer> {
    /**
     * {@code CXL_SEC_ENABLED_SANITIZE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "CXL_SEC_ENABLED_SANITIZE"
    )
    CXL_SEC_ENABLED_SANITIZE,

    /**
     * {@code CXL_SEC_ENABLED_SECURE_ERASE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "CXL_SEC_ENABLED_SECURE_ERASE"
    )
    CXL_SEC_ENABLED_SECURE_ERASE,

    /**
     * {@code CXL_SEC_ENABLED_GET_SECURITY_STATE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "CXL_SEC_ENABLED_GET_SECURITY_STATE"
    )
    CXL_SEC_ENABLED_GET_SECURITY_STATE,

    /**
     * {@code CXL_SEC_ENABLED_SET_PASSPHRASE = 3}
     */
    @EnumMember(
        value = 3L,
        name = "CXL_SEC_ENABLED_SET_PASSPHRASE"
    )
    CXL_SEC_ENABLED_SET_PASSPHRASE,

    /**
     * {@code CXL_SEC_ENABLED_DISABLE_PASSPHRASE = 4}
     */
    @EnumMember(
        value = 4L,
        name = "CXL_SEC_ENABLED_DISABLE_PASSPHRASE"
    )
    CXL_SEC_ENABLED_DISABLE_PASSPHRASE,

    /**
     * {@code CXL_SEC_ENABLED_UNLOCK = 5}
     */
    @EnumMember(
        value = 5L,
        name = "CXL_SEC_ENABLED_UNLOCK"
    )
    CXL_SEC_ENABLED_UNLOCK,

    /**
     * {@code CXL_SEC_ENABLED_FREEZE_SECURITY = 6}
     */
    @EnumMember(
        value = 6L,
        name = "CXL_SEC_ENABLED_FREEZE_SECURITY"
    )
    CXL_SEC_ENABLED_FREEZE_SECURITY,

    /**
     * {@code CXL_SEC_ENABLED_PASSPHRASE_SECURE_ERASE = 7}
     */
    @EnumMember(
        value = 7L,
        name = "CXL_SEC_ENABLED_PASSPHRASE_SECURE_ERASE"
    )
    CXL_SEC_ENABLED_PASSPHRASE_SECURE_ERASE,

    /**
     * {@code CXL_SEC_ENABLED_MAX = 8}
     */
    @EnumMember(
        value = 8L,
        name = "CXL_SEC_ENABLED_MAX"
    )
    CXL_SEC_ENABLED_MAX
  }
}
