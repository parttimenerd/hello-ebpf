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
 * Generated class for BPF runtime types that start with tcp
 */
@java.lang.SuppressWarnings("unused")
public final class TcpDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __tcp_ack_snd_check(Ptr<sock> sk, int ofo_possible) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__tcp_ao_do_lookup((const struct sock *)$arg1, $arg2, (const union tcp_ao_addr *)$arg3, $arg4, $arg5, $arg6, $arg7)")
  public static Ptr<tcp_ao_key> __tcp_ao_do_lookup(Ptr<sock> sk, int l3index, Ptr<tcp_ao_addr> addr,
      int family, char prefix, int sndid, int rcvid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__tcp_ao_key_cmp((const struct tcp_ao_key *)$arg1, $arg2, (const union tcp_ao_addr *)$arg3, $arg4, $arg5, $arg6, $arg7)")
  public static int __tcp_ao_key_cmp(Ptr<tcp_ao_key> key, int l3index, Ptr<tcp_ao_addr> addr,
      char prefixlen, int family, int sndid, int rcvid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __tcp_cleanup_rbuf(Ptr<sock> sk, int copied) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __tcp_close(Ptr<sock> sk, long timeout) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__tcp_get_metrics((const struct inetpeer_addr *)$arg1, (const struct inetpeer_addr *)$arg2, $arg3, $arg4)")
  public static Ptr<tcp_metrics_block> __tcp_get_metrics(Ptr<inetpeer_addr> saddr,
      Ptr<inetpeer_addr> daddr, Ptr<net> net, @Unsigned int hash) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__tcp_md5_do_add($arg1, (const union tcp_ao_addr *)$arg2, $arg3, $arg4, $arg5, $arg6, (const u8 *)$arg7, $arg8, $arg9)")
  public static int __tcp_md5_do_add(Ptr<sock> sk, Ptr<tcp_ao_addr> addr, int family,
      char prefixlen, int l3index, char flags, Ptr<java.lang.Character> newkey, char newkeylen,
      @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__tcp_md5_do_lookup((const struct sock *)$arg1, $arg2, (const union tcp_ao_addr *)$arg3, $arg4, $arg5)")
  public static Ptr<tcp_md5sig_key> __tcp_md5_do_lookup(Ptr<sock> sk, int l3index,
      Ptr<tcp_ao_addr> addr, int family, boolean any_l3index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __tcp_push_pending_frames(Ptr<sock> sk, @Unsigned int cur_mss, int nonagle) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __tcp_read_sock(Ptr<sock> sk, Ptr<read_descriptor_t> desc,
      @OriginalName("sk_read_actor_t") Ptr<?> recv_actor, boolean noack,
      Ptr<java.lang. @Unsigned Integer> copied_seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __tcp_retransmit_skb(Ptr<sock> sk, Ptr<sk_buff> skb, int segs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int __tcp_select_window(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __tcp_send_ack(Ptr<sock> sk, @Unsigned int rcv_nxt, @Unsigned short flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __tcp_sock_set_cork(Ptr<sock> sk, boolean on) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __tcp_sock_set_nodelay(Ptr<sock> sk, boolean on) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __tcp_sock_set_quickack(Ptr<sock> sk, int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __tcp_transmit_skb(Ptr<sock> sk, Ptr<sk_buff> skb, int clone_it,
      @Unsigned @OriginalName("gfp_t") int gfp_mask, @Unsigned int rcv_nxt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __tcp_v4_send_check(Ptr<sk_buff> skb,
      @Unsigned @OriginalName("__be32") int saddr, @Unsigned @OriginalName("__be32") int daddr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_abort(Ptr<sock> sk, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_abort_override(Ptr<sock> ssk, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_ack($arg1, (const struct sk_buff *)$arg2, $arg3)")
  public static int tcp_ack(Ptr<sock> sk, Ptr<sk_buff> skb, int flag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_ack_tstamp($arg1, $arg2, (const struct sk_buff *)$arg3, $arg4)")
  public static void tcp_ack_tstamp(Ptr<sock> sk, Ptr<sk_buff> skb, Ptr<sk_buff> ack_skb,
      @Unsigned int prior_snd_una) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_ack_update_rtt($arg1, (const int)$arg2, $arg3, $arg4, $arg5, $arg6)")
  public static boolean tcp_ack_update_rtt(Ptr<sock> sk, int flag, long seq_rtt_us,
      long sack_rtt_us, long ca_rtt_us, Ptr<rate_sample> rs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean tcp_add_backlog(Ptr<sock> sk, Ptr<sk_buff> skb,
      Ptr<skb_drop_reason> reason) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_add_reno_sack(Ptr<sock> sk, int num_dupack, boolean ece_ack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_adjust_pcount($arg1, (const struct sk_buff *)$arg2, $arg3)")
  public static void tcp_adjust_pcount(Ptr<sock> sk, Ptr<sk_buff> skb, int decr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_ao_add_cmd(Ptr<sock> sk, @Unsigned short family, sockptr_t optval,
      int optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<tcp_ao_info> tcp_ao_alloc_info(@Unsigned @OriginalName("gfp_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_ao_cache_traffic_keys((const struct sock *)$arg1, $arg2, $arg3)")
  public static int tcp_ao_cache_traffic_keys(Ptr<sock> sk, Ptr<tcp_ao_info> ao,
      Ptr<tcp_ao_key> ao_key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_ao_calc_key_skb($arg1, $arg2, (const struct sk_buff *)$arg3, $arg4, $arg5, $arg6)")
  public static int tcp_ao_calc_key_skb(Ptr<tcp_ao_key> mkt, Ptr<java.lang.Character> key,
      Ptr<sk_buff> skb, @Unsigned @OriginalName("__be32") int sisn,
      @Unsigned @OriginalName("__be32") int disn, int family) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_ao_calc_traffic_key(Ptr<tcp_ao_key> mkt, Ptr<java.lang.Character> key,
      Ptr<?> ctx, @Unsigned int len, Ptr<tcp_sigpool> hp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int tcp_ao_compute_sne(@Unsigned int next_sne, @Unsigned int next_seq,
      @Unsigned int seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_ao_connect_init(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_ao_copy_all_matching((const struct sock *)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int tcp_ao_copy_all_matching(Ptr<sock> sk, Ptr<sock> newsk, Ptr<request_sock> req,
      Ptr<sk_buff> skb, int family) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_ao_del_cmd(Ptr<sock> sk, @Unsigned short family, sockptr_t optval,
      int optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_ao_destroy_sock(Ptr<sock> sk, boolean twsk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_ao_do_lookup((const struct sock *)$arg1, $arg2, (const union tcp_ao_addr *)$arg3, $arg4, $arg5, $arg6)")
  public static Ptr<tcp_ao_key> tcp_ao_do_lookup(Ptr<sock> sk, int l3index, Ptr<tcp_ao_addr> addr,
      int family, int sndid, int rcvid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_ao_established(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_ao_established_key((const struct sock *)$arg1, $arg2, $arg3, $arg4)")
  public static Ptr<tcp_ao_key> tcp_ao_established_key(Ptr<sock> sk, Ptr<tcp_ao_info> ao, int sndid,
      int rcvid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_ao_finish_connect(Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_ao_get_mkts(Ptr<sock> sk, sockptr_t optval, sockptr_t optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_ao_get_repair(Ptr<sock> sk, sockptr_t optval, sockptr_t optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_ao_get_sock_info(Ptr<sock> sk, sockptr_t optval, sockptr_t optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_ao_hash_hdr($arg1, $arg2, $arg3, (const u8 *)$arg4, (const union tcp_ao_addr *)$arg5, (const union tcp_ao_addr *)$arg6, (const struct tcphdr *)$arg7, $arg8)")
  public static int tcp_ao_hash_hdr(@Unsigned short family, String ao_hash, Ptr<tcp_ao_key> key,
      Ptr<java.lang.Character> tkey, Ptr<tcp_ao_addr> daddr, Ptr<tcp_ao_addr> saddr, Ptr<tcphdr> th,
      @Unsigned int sne) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_ao_hash_skb($arg1, $arg2, $arg3, (const struct sock *)$arg4, (const struct sk_buff *)$arg5, (const u8 *)$arg6, $arg7, $arg8)")
  public static int tcp_ao_hash_skb(@Unsigned short family, String ao_hash, Ptr<tcp_ao_key> key,
      Ptr<sock> sk, Ptr<sk_buff> skb, Ptr<java.lang.Character> tkey, int hash_offset,
      @Unsigned int sne) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_ao_ignore_icmp((const struct sock *)$arg1, $arg2, $arg3, $arg4)")
  public static boolean tcp_ao_ignore_icmp(Ptr<sock> sk, int family, int type, int code) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_ao_inbound_lookup($arg1, (const struct sock *)$arg2, (const struct sk_buff *)$arg3, $arg4, $arg5, $arg6)")
  public static Ptr<tcp_ao_key> tcp_ao_inbound_lookup(@Unsigned short family, Ptr<sock> sk,
      Ptr<sk_buff> skb, int sndid, int rcvid, int l3index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_ao_info_free_rcu(Ptr<callback_head> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_ao_key_cmp((const struct tcp_ao_key *)$arg1, $arg2, (const union tcp_ao_addr *)$arg3, $arg4, $arg5, $arg6, $arg7)")
  public static int tcp_ao_key_cmp(Ptr<tcp_ao_key> key, int l3index, Ptr<tcp_ao_addr> addr,
      char prefixlen, int family, int sndid, int rcvid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_ao_key_free_rcu(Ptr<callback_head> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_ao_parse_crypto(Ptr<tcp_ao_add> cmd, Ptr<tcp_ao_key> key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_ao_prepare_reset((const struct sock *)$arg1, $arg2, (const struct tcp_ao_hdr *)$arg3, $arg4, $arg5, $arg6, $arg7, $arg8, $arg9, $arg10)")
  public static int tcp_ao_prepare_reset(Ptr<sock> sk, Ptr<sk_buff> skb, Ptr<tcp_ao_hdr> aoh,
      int l3index, @Unsigned int seq, Ptr<Ptr<tcp_ao_key>> key, Ptr<String> traffic_key,
      Ptr<java.lang. @OriginalName("bool") Boolean> allocated_traffic_key,
      Ptr<java.lang.Character> keyid, Ptr<java.lang. @Unsigned Integer> sne) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_ao_set_repair(Ptr<sock> sk, sockptr_t optval, @Unsigned int optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_ao_syncookie($arg1, (const struct sk_buff *)$arg2, $arg3, $arg4)")
  public static void tcp_ao_syncookie(Ptr<sock> sk, Ptr<sk_buff> skb, Ptr<request_sock> req,
      @Unsigned short family) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_ao_time_wait(Ptr<tcp_timewait_sock> tcptw, Ptr<tcp_sock> tp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_ao_transmit_skb(Ptr<sock> sk, Ptr<sk_buff> skb, Ptr<tcp_ao_key> key,
      Ptr<tcphdr> th, Ptr<java.lang.Character> hash_location) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_ao_verify_hash((const struct sock *)$arg1, (const struct sk_buff *)$arg2, $arg3, $arg4, (const struct tcp_ao_hdr *)$arg5, $arg6, $arg7, $arg8, $arg9, $arg10)")
  public static skb_drop_reason tcp_ao_verify_hash(Ptr<sock> sk, Ptr<sk_buff> skb,
      @Unsigned short family, Ptr<tcp_ao_info> info, Ptr<tcp_ao_hdr> aoh, Ptr<tcp_ao_key> key,
      Ptr<java.lang.Character> traffic_key, Ptr<java.lang.Character> phash, @Unsigned int sne,
      int l3index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_ao_verify_ipv6(Ptr<sock> sk, Ptr<tcp_ao_add> cmd,
      Ptr<Ptr<tcp_ao_addr>> paddr, Ptr<java.lang. @Unsigned Short> family) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_assign_congestion_control(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean tcp_bpf_bypass_getsockopt(int level, int optname) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_bpf_clone((const struct sock *)$arg1, $arg2)")
  public static void tcp_bpf_clone(Ptr<sock> sk, Ptr<sock> newsk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_bpf_push(Ptr<sock> sk, Ptr<sk_msg> msg, @Unsigned int apply_bytes,
      int flags, boolean uncharge) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_bpf_recvmsg(Ptr<sock> sk, Ptr<msghdr> msg, @Unsigned long len, int flags,
      Ptr<java.lang.Integer> addr_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_bpf_recvmsg_parser(Ptr<sock> sk, Ptr<msghdr> msg, @Unsigned long len,
      int flags, Ptr<java.lang.Integer> addr_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_bpf_send_verdict(Ptr<sock> sk, Ptr<sk_psock> psock, Ptr<sk_msg> msg,
      Ptr<java.lang.Integer> copied, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_bpf_sendmsg(Ptr<sock> sk, Ptr<msghdr> msg, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_bpf_sendmsg_redir(Ptr<sock> sk, boolean ingress, Ptr<sk_msg> msg,
      @Unsigned int bytes, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_bpf_strp_read_sock(Ptr<strparser> strp, Ptr<read_descriptor_t> desc,
      @OriginalName("sk_read_actor_t") Ptr<?> recv_actor) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_bpf_update_proto(Ptr<sock> sk, Ptr<sk_psock> psock, boolean restore) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_bpf_v4_build_proto() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_ca_find((const u8 *)$arg1)")
  public static Ptr<tcp_congestion_ops> tcp_ca_find(String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_ca_find_autoload((const u8 *)$arg1)")
  public static Ptr<tcp_congestion_ops> tcp_ca_find_autoload(String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<tcp_congestion_ops> tcp_ca_find_key(@Unsigned int key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_ca_get_key_by_name((const u8 *)$arg1, $arg2)")
  public static @Unsigned int tcp_ca_get_key_by_name(String name,
      Ptr<java.lang. @OriginalName("bool") Boolean> ecn_ca) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static String tcp_ca_get_name_by_key(@Unsigned int key, String buffer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_ca_openreq_child($arg1, (const struct dst_entry *)$arg2)")
  public static void tcp_ca_openreq_child(Ptr<sock> sk, Ptr<dst_entry> dst) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_can_repair_sock((const struct sock *)$arg1)")
  public static boolean tcp_can_repair_sock(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_check_dsack($arg1, (const struct sk_buff *)$arg2, $arg3, $arg4, $arg5, $arg6)")
  public static boolean tcp_check_dsack(Ptr<sock> sk, Ptr<sk_buff> ack_skb,
      Ptr<tcp_sack_block_wire> sp, int num_sacks, @Unsigned int prior_snd_una,
      Ptr<tcp_sacktag_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_check_oom((const struct sock *)$arg1, $arg2)")
  public static boolean tcp_check_oom(Ptr<sock> sk, int shift) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sock> tcp_check_req(Ptr<sock> sk, Ptr<sk_buff> skb, Ptr<request_sock> req,
      boolean fastopen, Ptr<java.lang. @OriginalName("bool") Boolean> req_stolen,
      Ptr<skb_drop_reason> drop_reason) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_check_sack_reordering($arg1, (const unsigned int)$arg2, (const int)$arg3)")
  public static void tcp_check_sack_reordering(Ptr<sock> sk, @Unsigned int low_seq, int ts) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_check_space(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static skb_drop_reason tcp_child_process(Ptr<sock> parent, Ptr<sock> child,
      Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_chrono_start($arg1, (const enum tcp_chrono)$arg2)")
  public static void tcp_chrono_start(Ptr<sock> sk, tcp_chrono type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_chrono_stop($arg1, (const enum tcp_chrono)$arg2)")
  public static void tcp_chrono_stop(Ptr<sock> sk, tcp_chrono type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_clamp_probe0_to_user_timeout((const struct sock *)$arg1, $arg2)")
  public static @Unsigned int tcp_clamp_probe0_to_user_timeout(Ptr<sock> sk, @Unsigned int when) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_clean_rtx_queue($arg1, (const struct sk_buff *)$arg2, $arg3, $arg4, $arg5, $arg6)")
  public static int tcp_clean_rtx_queue(Ptr<sock> sk, Ptr<sk_buff> ack_skb,
      @Unsigned int prior_fack, @Unsigned int prior_snd_una, Ptr<tcp_sacktag_state> sack,
      boolean ece_ack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_cleanup_congestion_control(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_cleanup_rbuf(Ptr<sock> sk, int copied) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_cleanup_ulp(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_clear_md5_list(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_clear_retrans(Ptr<tcp_sock> tp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int tcp_clock_ts(boolean usec_ts) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_clone_payload(Ptr<sock> sk, Ptr<sk_buff> to, int probe_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_close(Ptr<sock> sk, long timeout) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_collapse(Ptr<sock> sk, Ptr<sk_buff_head> list, Ptr<rb_root> root,
      Ptr<sk_buff> head, Ptr<sk_buff> tail, @Unsigned int start, @Unsigned int end) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sk_buff> tcp_collapse_one(Ptr<sock> sk, Ptr<sk_buff> skb,
      Ptr<sk_buff_head> list, Ptr<rb_root> root) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static hrtimer_restart tcp_compressed_ack_kick(Ptr<hrtimer> timer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  @me.bechberger.ebpf.annotations.bpf.KFunc(
      signature = "void tcp_cong_avoid_ai(struct tcp_sock *tp, unsigned int w, unsigned int acked)"
  )
  public static void tcp_cong_avoid_ai(Ptr<tcp_sock> tp, @Unsigned int w, @Unsigned int acked) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_congestion_default() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_conn_request($arg1, (const struct tcp_request_sock_ops *)$arg2, $arg3, $arg4)")
  public static int tcp_conn_request(Ptr<request_sock_ops> rsk_ops,
      Ptr<tcp_request_sock_ops> af_ops, Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_connect(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_connect_init(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_connect_queue_skb(Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_create_openreq_child((const struct sock *)$arg1, $arg2, $arg3)")
  public static Ptr<sock> tcp_create_openreq_child(Ptr<sock> sk, Ptr<request_sock> req,
      Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int tcp_current_mss(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_cwnd_reduction(Ptr<sock> sk, int newly_acked_sacked, int newly_lost,
      int flag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_cwnd_restart(Ptr<sock> sk, int delta) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_cwnd_validate(Ptr<sock> sk, boolean is_cwnd_limited) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_data_ecn_check($arg1, (const struct sk_buff *)$arg2)")
  public static void tcp_data_ecn_check(Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_data_queue(Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_data_queue_ofo(Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_data_ready(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_delack_max((const struct sock *)$arg1)")
  public static @Unsigned int tcp_delack_max(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_delack_timer(Ptr<timer_list> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_delack_timer_handler(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_disconnect(Ptr<sock> sk, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_do_parse_auth_options((const struct tcphdr *)$arg1, (const u8**)$arg2, (const u8**)$arg3)")
  public static int tcp_do_parse_auth_options(Ptr<tcphdr> th,
      Ptr<Ptr<java.lang.Character>> md5_hash, Ptr<Ptr<java.lang.Character>> ao_hash) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_done(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_done_with_error(Ptr<sock> sk, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_downgrade_zcopy_pure(Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_drop_reason(Ptr<sock> sk, Ptr<sk_buff> skb, skb_drop_reason reason) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_dsack_extend(Ptr<sock> sk, @Unsigned int seq, @Unsigned int end_seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_eat_skb(Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_enter_cwr(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_enter_loss(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_enter_memory_pressure(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_enter_recovery(Ptr<sock> sk, boolean ece_ack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int tcp_established_options(Ptr<sock> sk, Ptr<sk_buff> skb,
      Ptr<tcp_out_options> opts, Ptr<tcp_key> key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_event_data_recv(Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_event_new_data_sent(Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_fastopen_active_detect_blackhole(Ptr<sock> sk, boolean expired) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_fastopen_active_disable(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_fastopen_active_disable_ofo_check(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean tcp_fastopen_active_should_disable(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_fastopen_add_skb(Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_fastopen_cache_get(Ptr<sock> sk, Ptr<java.lang. @Unsigned Short> mss,
      Ptr<tcp_fastopen_cookie> cookie) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_fastopen_cache_set(Ptr<sock> sk, @Unsigned short mss,
      Ptr<tcp_fastopen_cookie> cookie, boolean syn_lost, @Unsigned short try_exp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean tcp_fastopen_cookie_check(Ptr<sock> sk, Ptr<java.lang. @Unsigned Short> mss,
      Ptr<tcp_fastopen_cookie> cookie) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_fastopen_cookie_gen_check(Ptr<sock> sk, Ptr<request_sock> req,
      Ptr<sk_buff> syn, Ptr<tcp_fastopen_cookie> orig, Ptr<tcp_fastopen_cookie> valid_foc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sock> tcp_fastopen_create_child(Ptr<sock> sk, Ptr<sk_buff> skb,
      Ptr<request_sock> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_fastopen_ctx_destroy(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_fastopen_ctx_free(Ptr<callback_head> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean tcp_fastopen_defer_connect(Ptr<sock> sk, Ptr<java.lang.Integer> err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_fastopen_destroy_cipher(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_fastopen_get_cipher(Ptr<net> net, Ptr<inet_connection_sock> icsk,
      Ptr<java.lang. @Unsigned Long> key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_fastopen_init_key_once(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_fastopen_reset_cipher(Ptr<net> net, Ptr<sock> sk, Ptr<?> primary_key,
      Ptr<?> backup_key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_fastopen_synack_timer(Ptr<sock> sk, Ptr<request_sock> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_fastretrans_alert($arg1, (const unsigned int)$arg2, $arg3, $arg4, $arg5)")
  public static void tcp_fastretrans_alert(Ptr<sock> sk, @Unsigned int prior_snd_una,
      int num_dupack, Ptr<java.lang.Integer> ack_flag, Ptr<java.lang.Integer> rexmit) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_filter(Ptr<sock> sk, Ptr<sk_buff> skb, Ptr<skb_drop_reason> reason) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_fin(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_finish_connect(Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_fragment(Ptr<sock> sk, tcp_queue tcp_queue, Ptr<sk_buff> skb,
      @Unsigned int len, @Unsigned int mss_now, @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_fragment_tstamp(Ptr<sk_buff> skb, Ptr<sk_buff> skb2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_free_fastopen_req(Ptr<tcp_sock> tp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_get_allowed_congestion_control(String buf, @Unsigned long maxlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_get_available_congestion_control(String buf, @Unsigned long maxlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_get_available_ulp(String buf, @Unsigned long maxlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sock> tcp_get_cookie_sock(Ptr<sock> sk, Ptr<sk_buff> skb, Ptr<request_sock> req,
      Ptr<dst_entry> dst) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_get_default_congestion_control(Ptr<net> net, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> tcp_get_idx(Ptr<seq_file> seq, @OriginalName("loff_t") long pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_get_info(Ptr<sock> sk, Ptr<tcp_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_get_info_chrono_stats((const struct tcp_sock *)$arg1, $arg2)")
  public static void tcp_get_info_chrono_stats(Ptr<tcp_sock> tp, Ptr<tcp_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<tcp_metrics_block> tcp_get_metrics(Ptr<sock> sk, Ptr<dst_entry> dst,
      boolean create) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_get_syncookie_mss($arg1, (const struct tcp_request_sock_ops *)$arg2, $arg3, $arg4)")
  public static @Unsigned short tcp_get_syncookie_mss(Ptr<request_sock_ops> rsk_ops,
      Ptr<tcp_request_sock_ops> af_ops, Ptr<sock> sk, Ptr<tcphdr> th) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_get_timestamping_opt_stats((const struct sock *)$arg1, (const struct sk_buff *)$arg2, (const struct sk_buff *)$arg3)")
  public static Ptr<sk_buff> tcp_get_timestamping_opt_stats(Ptr<sock> sk, Ptr<sk_buff> orig_skb,
      Ptr<sk_buff> ack_skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_getsockopt(Ptr<sock> sk, int level, int optname, String optval,
      Ptr<java.lang.Integer> optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_gro_complete(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sk_buff> tcp_gro_lookup(Ptr<list_head> head, Ptr<tcphdr> th) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<tcphdr> tcp_gro_pull_header(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sk_buff> tcp_gro_receive(Ptr<list_head> head, Ptr<sk_buff> skb,
      Ptr<tcphdr> th) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_grow_window($arg1, (const struct sk_buff *)$arg2, $arg3)")
  public static void tcp_grow_window(Ptr<sock> sk, Ptr<sk_buff> skb, boolean adjust) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sk_buff> tcp_gso_segment(Ptr<sk_buff> skb,
      @Unsigned @OriginalName("netdev_features_t") long features) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_identify_packet_loss(Ptr<sock> sk, Ptr<java.lang.Integer> ack_flag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_in_ack_event(Ptr<sock> sk, int flag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_inbound_ao_hash($arg1, (const struct sk_buff *)$arg2, $arg3, (const struct request_sock *)$arg4, $arg5, (const struct tcp_ao_hdr *)$arg6)")
  public static skb_drop_reason tcp_inbound_ao_hash(Ptr<sock> sk, Ptr<sk_buff> skb,
      @Unsigned short family, Ptr<request_sock> req, int l3index, Ptr<tcp_ao_hdr> aoh) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_inbound_hash($arg1, (const struct request_sock *)$arg2, (const struct sk_buff *)$arg3, (const void *)$arg4, (const void *)$arg5, $arg6, $arg7, $arg8)")
  public static skb_drop_reason tcp_inbound_hash(Ptr<sock> sk, Ptr<request_sock> req,
      Ptr<sk_buff> skb, Ptr<?> saddr, Ptr<?> daddr, int family, int dif, int sdif) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_init_congestion_control(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_init_cwnd((const struct tcp_sock *)$arg1, (const struct dst_entry *)$arg2)")
  public static @Unsigned int tcp_init_cwnd(Ptr<tcp_sock> tp, Ptr<dst_entry> dst) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_init_metrics(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_init_sock(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_init_transfer(Ptr<sock> sk, int bpf_op, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_init_tso_segs(Ptr<sk_buff> skb, @Unsigned int mss_now) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_init_xmit_timers(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_initialize_rcv_mss(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_inq_hint(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_ioctl(Ptr<sock> sk, int cmd, Ptr<java.lang.Integer> karg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean tcp_is_ulp_esp(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_keepalive_timer(Ptr<timer_list> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_ld_RTO_revert(Ptr<sock> sk, @Unsigned int seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_leave_memory_pressure(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_make_synack((const struct sock *)$arg1, $arg2, $arg3, $arg4, $arg5, $arg6)")
  public static Ptr<sk_buff> tcp_make_synack(Ptr<sock> sk, Ptr<dst_entry> dst,
      Ptr<request_sock> req, Ptr<tcp_fastopen_cookie> foc, tcp_synack_type synack_type,
      Ptr<sk_buff> syn_skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_mark_push(Ptr<tcp_sock> tp, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_mark_skb_lost(Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_match_skb_to_sack(Ptr<sock> sk, Ptr<sk_buff> skb, @Unsigned int start_seq,
      @Unsigned int end_seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_md5_add_sigpool() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_md5_alloc_sigpool() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_md5_do_add($arg1, (const union tcp_ao_addr *)$arg2, $arg3, $arg4, $arg5, $arg6, (const u8 *)$arg7, $arg8)")
  public static int tcp_md5_do_add(Ptr<sock> sk, Ptr<tcp_ao_addr> addr, int family, char prefixlen,
      int l3index, char flags, Ptr<java.lang.Character> newkey, char newkeylen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_md5_do_del($arg1, (const union tcp_ao_addr *)$arg2, $arg3, $arg4, $arg5, $arg6)")
  public static int tcp_md5_do_del(Ptr<sock> sk, Ptr<tcp_ao_addr> addr, int family, char prefixlen,
      int l3index, char flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_md5_do_lookup_exact((const struct sock *)$arg1, (const union tcp_ao_addr *)$arg2, $arg3, $arg4, $arg5, $arg6)")
  public static Ptr<tcp_md5sig_key> tcp_md5_do_lookup_exact(Ptr<sock> sk, Ptr<tcp_ao_addr> addr,
      int family, char prefixlen, int l3index, char flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_md5_hash_key($arg1, (const struct tcp_md5sig_key *)$arg2)")
  public static int tcp_md5_hash_key(Ptr<tcp_sigpool> hp, Ptr<tcp_md5sig_key> key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_md5_key_copy($arg1, (const union tcp_ao_addr *)$arg2, $arg3, $arg4, $arg5, $arg6)")
  public static int tcp_md5_key_copy(Ptr<sock> sk, Ptr<tcp_ao_addr> addr, int family,
      char prefixlen, int l3index, Ptr<tcp_md5sig_key> key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_md5_release_sigpool() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_md5_twsk_free_rcu(Ptr<callback_head> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_md5sig_info_free_rcu(Ptr<callback_head> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_measure_rcv_mss($arg1, (const struct sk_buff *)$arg2)")
  public static void tcp_measure_rcv_mss(Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_metrics_fill_info(Ptr<sk_buff> msg, Ptr<tcp_metrics_block> tm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_metrics_flush_all(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_metrics_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_metrics_nl_cmd_del(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_metrics_nl_cmd_get(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_metrics_nl_dump(Ptr<sk_buff> skb, Ptr<netlink_callback> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_mmap(Ptr<file> file, Ptr<socket> sock, Ptr<vm_area_struct> vma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_msg_wait_data(Ptr<sock> sk, Ptr<sk_psock> psock, long timeo) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_mss_to_mtu(Ptr<sock> sk, int mss) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_mstamp_refresh(Ptr<tcp_sock> tp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_mtu_probe(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_mtu_to_mss(Ptr<sock> sk, int pmtu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_mtup_init(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_net_metrics_exit_batch(Ptr<list_head> net_exit_list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int tcp_newly_delivered(Ptr<sock> sk, @Unsigned int prior_delivered,
      int flag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_newreno_mark_lost(Ptr<sock> sk, boolean snd_una_advanced) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_non_congestion_loss_retransmit(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_ofo_queue(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_oow_rate_limited($arg1, (const struct sk_buff *)$arg2, $arg3, $arg4)")
  public static boolean tcp_oow_rate_limited(Ptr<net> net, Ptr<sk_buff> skb, int mib_idx,
      Ptr<java.lang. @Unsigned Integer> last_oow_ack_time) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_openreq_init_rwin($arg1, (const struct sock *)$arg2, (const struct dst_entry *)$arg3)")
  public static void tcp_openreq_init_rwin(Ptr<request_sock> req, Ptr<sock> sk_listener,
      Ptr<dst_entry> dst) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_options_write($arg1, $arg2, (const struct tcp_request_sock *)$arg3, $arg4, $arg5)")
  public static void tcp_options_write(Ptr<tcphdr> th, Ptr<tcp_sock> tp,
      Ptr<tcp_request_sock> tcprsk, Ptr<tcp_out_options> opts, Ptr<tcp_key> key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_orphan_count_sum() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_orphan_update(Ptr<timer_list> unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_out_of_resources(Ptr<sock> sk, boolean do_reset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static hrtimer_restart tcp_pace_kick(Ptr<hrtimer> timer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_parse_ao(Ptr<sock> sk, int cmd, @Unsigned short family, sockptr_t optval,
      int optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_parse_fastopen_option($arg1, (const u8 *)$arg2, $arg3, $arg4, $arg5)")
  public static void tcp_parse_fastopen_option(int len, String cookie, boolean syn,
      Ptr<tcp_fastopen_cookie> foc, boolean exp_opt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_parse_mss_option((const struct tcphdr *)$arg1, $arg2)")
  public static @Unsigned short tcp_parse_mss_option(Ptr<tcphdr> th, @Unsigned short user_mss) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_parse_options((const struct net *)$arg1, (const struct sk_buff *)$arg2, $arg3, $arg4, $arg5)")
  public static void tcp_parse_options(Ptr<net> net, Ptr<sk_buff> skb,
      Ptr<tcp_options_received> opt_rx, int estab, Ptr<tcp_fastopen_cookie> foc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_peek_len(Ptr<socket> sock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean tcp_peer_is_proven(Ptr<request_sock> req, Ptr<dst_entry> dst) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_plb_check_rehash(Ptr<sock> sk, Ptr<tcp_plb_state> plb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_plb_update_state((const struct sock *)$arg1, $arg2, (const int)$arg3)")
  public static void tcp_plb_update_state(Ptr<sock> sk, Ptr<tcp_plb_state> plb, int cong_ratio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_plb_update_state_upon_rto(Ptr<sock> sk, Ptr<tcp_plb_state> plb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("__poll_t") int tcp_poll(Ptr<file> file, Ptr<socket> sock,
      Ptr<poll_table_struct> wait) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_probe_timer(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_process_tlp_ack(Ptr<sock> sk, @Unsigned int ack, int flag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_prune_ofo_queue($arg1, (const struct sk_buff *)$arg2)")
  public static boolean tcp_prune_ofo_queue(Ptr<sock> sk, Ptr<sk_buff> in_skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_prune_queue($arg1, (const struct sk_buff *)$arg2)")
  public static int tcp_prune_queue(Ptr<sock> sk, Ptr<sk_buff> in_skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_push(Ptr<sock> sk, int flags, int mss_now, int nonagle, int size_goal) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_push_one(Ptr<sock> sk, @Unsigned int mss_now) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_queue_rcv(Ptr<sock> sk, Ptr<sk_buff> skb,
      Ptr<java.lang. @OriginalName("bool") Boolean> fragstolen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_rack_advance(Ptr<tcp_sock> tp, char sacked, @Unsigned int end_seq,
      @Unsigned long xmit_time) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_rack_detect_loss(Ptr<sock> sk,
      Ptr<java.lang. @Unsigned Integer> reo_timeout) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean tcp_rack_mark_lost(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_rack_reo_timeout(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_rack_skb_timeout(Ptr<tcp_sock> tp, Ptr<sk_buff> skb,
      @Unsigned int reo_wnd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_rack_update_reo_wnd(Ptr<sock> sk, Ptr<rate_sample> rs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_rate_check_app_limited(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_rate_gen(Ptr<sock> sk, @Unsigned int delivered, @Unsigned int lost,
      boolean is_sack_reneg, Ptr<rate_sample> rs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_rate_skb_delivered(Ptr<sock> sk, Ptr<sk_buff> skb, Ptr<rate_sample> rs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_rate_skb_sent(Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_rbtree_insert(Ptr<rb_root> root, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_rcv_established(Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean tcp_rcv_fastopen_synack(Ptr<sock> sk, Ptr<sk_buff> synack,
      Ptr<tcp_fastopen_cookie> cookie) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_rcv_sne_update(Ptr<tcp_sock> tp, @Unsigned int seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_rcv_space_adjust(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_rcv_spurious_retrans($arg1, (const struct sk_buff *)$arg2)")
  public static void tcp_rcv_spurious_retrans(Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static skb_drop_reason tcp_rcv_state_process(Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_rcv_synrecv_state_fastopen(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_rcv_synsent_state_process($arg1, $arg2, (const struct tcphdr *)$arg3)")
  public static int tcp_rcv_synsent_state_process(Ptr<sock> sk, Ptr<sk_buff> skb, Ptr<tcphdr> th) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_rcvbuf_grow(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_read_done(Ptr<sock> sk, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_read_skb(Ptr<sock> sk,
      @OriginalName("skb_read_actor_t") Ptr<?> recv_actor) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_read_sock(Ptr<sock> sk, Ptr<read_descriptor_t> desc,
      @OriginalName("sk_read_actor_t") Ptr<?> recv_actor) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_read_sock_noack(Ptr<sock> sk, Ptr<read_descriptor_t> desc,
      @OriginalName("sk_read_actor_t") Ptr<?> recv_actor, boolean noack,
      Ptr<java.lang. @Unsigned Integer> copied_seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_rearm_rto(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sk_buff> tcp_recv_skb(Ptr<sock> sk, @Unsigned int seq,
      Ptr<java.lang. @Unsigned Integer> off) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_recv_timestamp($arg1, (const struct sock *)$arg2, $arg3)")
  public static void tcp_recv_timestamp(Ptr<msghdr> msg, Ptr<sock> sk,
      Ptr<scm_timestamping_internal> tss) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_recvmsg(Ptr<sock> sk, Ptr<msghdr> msg, @Unsigned long len, int flags,
      Ptr<java.lang.Integer> addr_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_recvmsg_dmabuf($arg1, (const struct sk_buff *)$arg2, $arg3, $arg4, $arg5)")
  public static int tcp_recvmsg_dmabuf(Ptr<sock> sk, Ptr<sk_buff> skb, @Unsigned int offset,
      Ptr<msghdr> msg, int remaining_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_recvmsg_locked(Ptr<sock> sk, Ptr<msghdr> msg, @Unsigned long len, int flags,
      Ptr<scm_timestamping_internal> tss, Ptr<java.lang.Integer> cmsg_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_register_congestion_control(Ptr<tcp_congestion_ops> ca) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_register_ulp(Ptr<tcp_ulp_ops> ulp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_release_cb(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_release_cb_override(Ptr<sock> ssk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_remove_empty_skb(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  @me.bechberger.ebpf.annotations.bpf.KFunc(
      signature = "void tcp_reno_cong_avoid(struct sock *sk, unsigned int ack, unsigned int acked)"
  )
  public static void tcp_reno_cong_avoid(Ptr<sock> sk, @Unsigned int ack, @Unsigned int acked) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  @me.bechberger.ebpf.annotations.bpf.KFunc(
      signature = "unsigned int tcp_reno_ssthresh(struct sock *sk)"
  )
  public static @Unsigned int tcp_reno_ssthresh(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  @me.bechberger.ebpf.annotations.bpf.KFunc(
      signature = "unsigned int tcp_reno_undo_cwnd(struct sock *sk)"
  )
  public static @Unsigned int tcp_reno_undo_cwnd(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_repair_options_est(Ptr<sock> sk, sockptr_t optbuf, @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_req_err(Ptr<sock> sk, @Unsigned int seq, boolean abort) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_reqsk_record_syn((const struct sock *)$arg1, $arg2, (const struct sk_buff *)$arg3)")
  public static void tcp_reqsk_record_syn(Ptr<sock> sk, Ptr<request_sock> req, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_reset(Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_reset_keepalive_timer(Ptr<sock> sk, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_retrans_try_collapse(Ptr<sock> sk, Ptr<sk_buff> to, int space) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_retransmit_skb(Ptr<sock> sk, Ptr<sk_buff> skb, int segs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_retransmit_timer(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_rtt_estimator(Ptr<sock> sk, long mrtt_us) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_rtx_synack((const struct sock *)$arg1, $arg2)")
  public static int tcp_rtx_synack(Ptr<sock> sk, Ptr<request_sock> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_sack_compress_send_ack(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_sack_new_ofo_skb(Ptr<sock> sk, @Unsigned int seq, @Unsigned int end_seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static char tcp_sacktag_one(Ptr<sock> sk, Ptr<tcp_sacktag_state> state, char sacked,
      @Unsigned int start_seq, @Unsigned int end_seq, int dup_sack, int pcount,
      @Unsigned long xmit_time) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sk_buff> tcp_sacktag_walk(Ptr<sk_buff> skb, Ptr<sock> sk,
      Ptr<tcp_sack_block> next_dup, Ptr<tcp_sacktag_state> state, @Unsigned int start_seq,
      @Unsigned int end_seq, boolean dup_sack_in) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_sacktag_write_queue($arg1, (const struct sk_buff *)$arg2, $arg3, $arg4)")
  public static int tcp_sacktag_write_queue(Ptr<sock> sk, Ptr<sk_buff> ack_skb,
      @Unsigned int prior_snd_una, Ptr<tcp_sacktag_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean tcp_schedule_loss_probe(Ptr<sock> sk, boolean advancing_rto) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_select_initial_window((const struct sock *)$arg1, $arg2, $arg3, $arg4, $arg5, $arg6, $arg7, $arg8)")
  public static void tcp_select_initial_window(Ptr<sock> sk, int __space, @Unsigned int mss,
      Ptr<java.lang. @Unsigned Integer> rcv_wnd, Ptr<java.lang. @Unsigned Integer> __window_clamp,
      int wscale_ok, Ptr<java.lang.Character> rcv_wscale, @Unsigned int init_rcv_wnd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_send_ack(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_send_active_reset(Ptr<sock> sk,
      @Unsigned @OriginalName("gfp_t") int priority, sk_rst_reason reason) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_send_challenge_ack(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_send_delayed_ack(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_send_dupack($arg1, (const struct sk_buff *)$arg2)")
  public static void tcp_send_dupack(Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_send_fin(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_send_loss_probe(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_send_mss(Ptr<sock> sk, Ptr<java.lang.Integer> size_goal, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_send_probe0(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_send_rcvq(Ptr<sock> sk, Ptr<msghdr> msg, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_send_syn_data(Ptr<sock> sk, Ptr<sk_buff> syn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_send_synack(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_send_window_probe(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_sendmsg(Ptr<sock> sk, Ptr<msghdr> msg, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_sendmsg_fastopen(Ptr<sock> sk, Ptr<msghdr> msg,
      Ptr<java.lang.Integer> copied, @Unsigned long size, Ptr<ubuf_info> uarg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_sendmsg_locked(Ptr<sock> sk, Ptr<msghdr> msg, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> tcp_seq_next(Ptr<seq_file> seq, Ptr<?> v,
      Ptr<java.lang. @OriginalName("loff_t") Long> pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> tcp_seq_start(Ptr<seq_file> seq,
      Ptr<java.lang. @OriginalName("loff_t") Long> pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_seq_stop(Ptr<seq_file> seq, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_set_allowed_congestion_control(String val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_set_ca_state($arg1, (const u8)$arg2)")
  public static void tcp_set_ca_state(Ptr<sock> sk, char ca_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_set_congestion_control($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static int tcp_set_congestion_control(Ptr<sock> sk, String name, boolean load,
      boolean cap_net_admin) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_set_default_congestion_control($arg1, (const u8 *)$arg2)")
  public static int tcp_set_default_congestion_control(Ptr<net> net, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_set_keepalive(Ptr<sock> sk, int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_set_rcvlowat(Ptr<sock> sk, int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_set_state(Ptr<sock> sk, int state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_set_ulp($arg1, (const u8 *)$arg2)")
  public static int tcp_set_ulp(Ptr<sock> sk, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_set_window_clamp(Ptr<sock> sk, int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_setsockopt(Ptr<sock> sk, int level, int optname, sockptr_t optval,
      @Unsigned int optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sk_buff> tcp_shift_skb_data(Ptr<sock> sk, Ptr<sk_buff> skb,
      Ptr<tcp_sacktag_state> state, @Unsigned int start_seq, @Unsigned int end_seq,
      boolean dup_sack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean tcp_shifted_skb(Ptr<sock> sk, Ptr<sk_buff> prev, Ptr<sk_buff> skb,
      Ptr<tcp_sacktag_state> state, @Unsigned int pcount, int shifted, int mss, boolean dup_sack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_shutdown(Ptr<sock> sk, int how) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long tcp_sigpool_algo(@Unsigned int id, String buf,
      @Unsigned long buf_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_sigpool_alloc_ahash((const u8 *)$arg1, $arg2)")
  public static int tcp_sigpool_alloc_ahash(String alg, @Unsigned long scratch_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_sigpool_end(Ptr<tcp_sigpool> c) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_sigpool_get(@Unsigned int id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_sigpool_hash_skb_data($arg1, (const struct sk_buff *)$arg2, $arg3)")
  public static int tcp_sigpool_hash_skb_data(Ptr<tcp_sigpool> hp, Ptr<sk_buff> skb,
      @Unsigned int header_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_sigpool_release(@Unsigned int id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_sigpool_start(@Unsigned int id, Ptr<tcp_sigpool> c) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_simple_retransmit(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_sk_exit(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_sk_exit_batch(Ptr<list_head> net_exit_list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_sk_init(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_skb_can_collapse((const struct sk_buff *)$arg1, (const struct sk_buff *)$arg2)")
  public static boolean tcp_skb_can_collapse(Ptr<sk_buff> to, Ptr<sk_buff> from) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_skb_collapse_tstamp($arg1, (const struct sk_buff *)$arg2)")
  public static void tcp_skb_collapse_tstamp(Ptr<sk_buff> skb, Ptr<sk_buff> next_skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_skb_entail(Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_skb_shift(Ptr<sk_buff> to, Ptr<sk_buff> from, int pcount, int shiftlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  @me.bechberger.ebpf.annotations.bpf.KFunc(
      signature = "unsigned int tcp_slow_start(struct tcp_sock *tp, unsigned int acked)"
  )
  public static @Unsigned int tcp_slow_start(Ptr<tcp_sock> tp, @Unsigned int acked) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_sndbuf_expand(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_sock_set_cork(Ptr<sock> sk, boolean on) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_sock_set_keepcnt(Ptr<sock> sk, int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_sock_set_keepidle(Ptr<sock> sk, int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_sock_set_keepidle_locked(Ptr<sock> sk, int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_sock_set_keepintvl(Ptr<sock> sk, int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_sock_set_maxseg(Ptr<sock> sk, int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_sock_set_nodelay(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_sock_set_quickack(Ptr<sock> sk, int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_sock_set_syncnt(Ptr<sock> sk, int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_sock_set_user_timeout(Ptr<sock> sk, int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_splice_data_recv(Ptr<read_descriptor_t> rd_desc, Ptr<sk_buff> skb,
      @Unsigned int offset, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_splice_eof(Ptr<socket> sock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long tcp_splice_read(Ptr<socket> sock,
      Ptr<java.lang. @OriginalName("loff_t") Long> ppos, Ptr<pipe_inode_info> pipe,
      @Unsigned long len, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sk_buff> tcp_stream_alloc_skb(Ptr<sock> sk,
      @Unsigned @OriginalName("gfp_t") int gfp, boolean force_schedule) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_stream_memory_free((const struct sock *)$arg1, $arg2)")
  public static boolean tcp_stream_memory_free(Ptr<sock> sk, int wake) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_syn_ack_timeout((const struct request_sock *)$arg1)")
  public static void tcp_syn_ack_timeout(Ptr<request_sock> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_syn_flood_action($arg1, (const u8 *)$arg2)")
  public static boolean tcp_syn_flood_action(Ptr<sock> sk, String proto) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int tcp_syn_options(Ptr<sock> sk, Ptr<sk_buff> skb,
      Ptr<tcp_out_options> opts, Ptr<tcp_key> key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_synack_options((const struct sock *)$arg1, $arg2, $arg3, $arg4, $arg5, (const struct tcp_key *)$arg6, $arg7, $arg8, $arg9)")
  public static @Unsigned int tcp_synack_options(Ptr<sock> sk, Ptr<request_sock> req,
      @Unsigned int mss, Ptr<sk_buff> skb, Ptr<tcp_out_options> opts, Ptr<tcp_key> key,
      Ptr<tcp_fastopen_cookie> foc, tcp_synack_type synack_type, Ptr<sk_buff> syn_skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_synack_rtt_meas(Ptr<sock> sk, Ptr<request_sock> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int tcp_sync_mss(Ptr<sock> sk, @Unsigned int pmtu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_time_wait(Ptr<sock> sk, int state, int timeo) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int tcp_timeout_init(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_timewait_state_process($arg1, $arg2, (const struct tcphdr *)$arg3, $arg4, $arg5)")
  public static tcp_tw_status tcp_timewait_state_process(Ptr<inet_timewait_sock> tw,
      Ptr<sk_buff> skb, Ptr<tcphdr> th, Ptr<java.lang. @Unsigned Integer> tw_isn,
      Ptr<skb_drop_reason> drop_reason) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_trim_head(Ptr<sock> sk, Ptr<sk_buff> skb, @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean tcp_try_coalesce(Ptr<sock> sk, Ptr<sk_buff> to, Ptr<sk_buff> from,
      Ptr<java.lang. @OriginalName("bool") Boolean> fragstolen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_try_fastopen($arg1, $arg2, $arg3, $arg4, (const struct dst_entry *)$arg5)")
  public static Ptr<sock> tcp_try_fastopen(Ptr<sock> sk, Ptr<sk_buff> skb, Ptr<request_sock> req,
      Ptr<tcp_fastopen_cookie> foc, Ptr<dst_entry> dst) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_try_keep_open(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_try_rmem_schedule($arg1, (const struct sk_buff *)$arg2, $arg3)")
  public static int tcp_try_rmem_schedule(Ptr<sock> sk, Ptr<sk_buff> skb, @Unsigned int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_try_to_open(Ptr<sock> sk, int flag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean tcp_try_undo_loss(Ptr<sock> sk, boolean frto_undo) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean tcp_try_undo_recovery(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int tcp_tso_segs(Ptr<sock> sk, @Unsigned int mss_now) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean tcp_tso_should_defer(Ptr<sock> sk, Ptr<sk_buff> skb,
      Ptr<java.lang. @OriginalName("bool") Boolean> is_cwnd_limited,
      Ptr<java.lang. @OriginalName("bool") Boolean> is_rwnd_limited, @Unsigned int max_segs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_tsq_work_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_tsq_workfn(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_tsq_write(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_twsk_destructor(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_twsk_purge(Ptr<list_head> net_exit_list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_twsk_unique(Ptr<sock> sk, Ptr<sock> sktw, Ptr<?> twp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_undo_cwnd_reduction(Ptr<sock> sk, boolean unmark_loss) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_unregister_congestion_control(Ptr<tcp_congestion_ops> ca) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_unregister_ulp(Ptr<tcp_ulp_ops> ulp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_update_congestion_control(Ptr<tcp_congestion_ops> ca,
      Ptr<tcp_congestion_ops> old_ca) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_update_metrics(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_update_pacing_rate(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_update_recv_tstamps(Ptr<sk_buff> skb, Ptr<scm_timestamping_internal> tss) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_update_skb_after_send(Ptr<sock> sk, Ptr<sk_buff> skb,
      @Unsigned long prior_wstamp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_update_ulp($arg1, $arg2, (void (*)(struct sock*))$arg3)")
  public static void tcp_update_ulp(Ptr<sock> sk, Ptr<proto> proto, Ptr<?> write_space) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_urg($arg1, $arg2, (const struct tcphdr *)$arg3)")
  public static void tcp_urg(Ptr<sock> sk, Ptr<sk_buff> skb, Ptr<tcphdr> th) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_v4_ao_calc_key(Ptr<tcp_ao_key> mkt, Ptr<java.lang.Character> key,
      @Unsigned @OriginalName("__be32") int saddr, @Unsigned @OriginalName("__be32") int daddr,
      @Unsigned @OriginalName("__be16") short sport, @Unsigned @OriginalName("__be16") short dport,
      @Unsigned @OriginalName("__be32") int sisn, @Unsigned @OriginalName("__be32") int disn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_v4_ao_calc_key_rsk(Ptr<tcp_ao_key> mkt, Ptr<java.lang.Character> key,
      Ptr<request_sock> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_v4_ao_calc_key_sk($arg1, $arg2, (const struct sock *)$arg3, $arg4, $arg5, $arg6)")
  public static int tcp_v4_ao_calc_key_sk(Ptr<tcp_ao_key> mkt, Ptr<java.lang.Character> key,
      Ptr<sock> sk, @Unsigned @OriginalName("__be32") int sisn,
      @Unsigned @OriginalName("__be32") int disn, boolean send) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_v4_ao_hash_skb($arg1, $arg2, (const struct sock *)$arg3, (const struct sk_buff *)$arg4, (const u8 *)$arg5, $arg6, $arg7)")
  public static int tcp_v4_ao_hash_skb(String ao_hash, Ptr<tcp_ao_key> key, Ptr<sock> sk,
      Ptr<sk_buff> skb, Ptr<java.lang.Character> tkey, int hash_offset, @Unsigned int sne) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_v4_ao_lookup((const struct sock *)$arg1, $arg2, $arg3, $arg4)")
  public static Ptr<tcp_ao_key> tcp_v4_ao_lookup(Ptr<sock> sk, Ptr<sock> addr_sk, int sndid,
      int rcvid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_v4_ao_lookup_rsk((const struct sock *)$arg1, $arg2, $arg3, $arg4)")
  public static Ptr<tcp_ao_key> tcp_v4_ao_lookup_rsk(Ptr<sock> sk, Ptr<request_sock> req, int sndid,
      int rcvid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_v4_ao_sign_reset((const struct sock *)$arg1, $arg2, (const struct tcp_ao_hdr *)$arg3, $arg4, $arg5, $arg6)")
  public static boolean tcp_v4_ao_sign_reset(Ptr<sock> sk, Ptr<sk_buff> skb, Ptr<tcp_ao_hdr> aoh,
      Ptr<ip_reply_arg> arg, Ptr<tcphdr> reply,
      Ptr<java.lang. @Unsigned @OriginalName("__be32") Integer> reply_options) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_v4_ao_synack_hash($arg1, $arg2, $arg3, (const struct sk_buff *)$arg4, $arg5, $arg6)")
  public static int tcp_v4_ao_synack_hash(String ao_hash, Ptr<tcp_ao_key> ao_key,
      Ptr<request_sock> req, Ptr<sk_buff> skb, int hash_offset, @Unsigned int sne) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_v4_conn_request(Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_v4_connect(Ptr<sock> sk, Ptr<sockaddr> uaddr, int addr_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_v4_destroy_sock(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_v4_do_rcv(Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_v4_early_demux(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_v4_err(Ptr<sk_buff> skb, @Unsigned int info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_v4_fill_cb($arg1, (const struct iphdr *)$arg2, (const struct tcphdr *)$arg3)")
  public static void tcp_v4_fill_cb(Ptr<sk_buff> skb, Ptr<iphdr> iph, Ptr<tcphdr> th) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned short tcp_v4_get_syncookie(Ptr<sock> sk, Ptr<iphdr> iph, Ptr<tcphdr> th,
      Ptr<java.lang. @Unsigned Integer> cookie) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_v4_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_v4_init_seq((const struct sk_buff *)$arg1)")
  public static @Unsigned int tcp_v4_init_seq(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_v4_init_sock(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_v4_init_ts_off((const struct net *)$arg1, (const struct sk_buff *)$arg2)")
  public static @Unsigned int tcp_v4_init_ts_off(Ptr<net> net, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_v4_md5_hash_hdr($arg1, (const struct tcp_md5sig_key *)$arg2, $arg3, $arg4, (const struct tcphdr *)$arg5)")
  public static int tcp_v4_md5_hash_hdr(String md5_hash, Ptr<tcp_md5sig_key> key,
      @Unsigned @OriginalName("__be32") int daddr, @Unsigned @OriginalName("__be32") int saddr,
      Ptr<tcphdr> th) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_v4_md5_hash_headers($arg1, $arg2, $arg3, (const struct tcphdr *)$arg4, $arg5)")
  public static int tcp_v4_md5_hash_headers(Ptr<tcp_sigpool> hp,
      @Unsigned @OriginalName("__be32") int daddr, @Unsigned @OriginalName("__be32") int saddr,
      Ptr<tcphdr> th, int nbytes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_v4_md5_hash_skb($arg1, (const struct tcp_md5sig_key *)$arg2, (const struct sock *)$arg3, (const struct sk_buff *)$arg4)")
  public static int tcp_v4_md5_hash_skb(String md5_hash, Ptr<tcp_md5sig_key> key, Ptr<sock> sk,
      Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_v4_md5_lookup((const struct sock *)$arg1, (const struct sock *)$arg2)")
  public static Ptr<tcp_md5sig_key> tcp_v4_md5_lookup(Ptr<sock> sk, Ptr<sock> addr_sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_v4_mtu_reduced(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_v4_parse_ao(Ptr<sock> sk, int cmd, sockptr_t optval, int optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_v4_parse_md5_keys(Ptr<sock> sk, int optname, sockptr_t optval, int optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_v4_pre_connect(Ptr<sock> sk, Ptr<sockaddr> uaddr, int addr_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_v4_rcv(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_v4_reqsk_destructor(Ptr<request_sock> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_v4_reqsk_send_ack((const struct sock *)$arg1, $arg2, $arg3)")
  public static void tcp_v4_reqsk_send_ack(Ptr<sock> sk, Ptr<sk_buff> skb, Ptr<request_sock> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_v4_restore_cb(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_v4_route_req((const struct sock *)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static Ptr<dst_entry> tcp_v4_route_req(Ptr<sock> sk, Ptr<sk_buff> skb, Ptr<flowi> fl,
      Ptr<request_sock> req, @Unsigned int tw_isn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_v4_send_ack((const struct sock *)$arg1, $arg2, $arg3, $arg4, $arg5, $arg6, $arg7, $arg8, $arg9, $arg10, $arg11, $arg12)")
  public static void tcp_v4_send_ack(Ptr<sock> sk, Ptr<sk_buff> skb, @Unsigned int seq,
      @Unsigned int ack, @Unsigned int win, @Unsigned int tsval, @Unsigned int tsecr, int oif,
      Ptr<tcp_key> key, int reply_flags, char tos, @Unsigned int txhash) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_v4_send_check(Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_v4_send_reset((const struct sock *)$arg1, $arg2, $arg3)")
  public static void tcp_v4_send_reset(Ptr<sock> sk, Ptr<sk_buff> skb, sk_rst_reason reason) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_v4_send_synack((const struct sock *)$arg1, $arg2, $arg3, $arg4, $arg5, $arg6, $arg7)")
  public static int tcp_v4_send_synack(Ptr<sock> sk, Ptr<dst_entry> dst, Ptr<flowi> fl,
      Ptr<request_sock> req, Ptr<tcp_fastopen_cookie> foc, tcp_synack_type synack_type,
      Ptr<sk_buff> syn_skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_v4_syn_recv_sock((const struct sock *)$arg1, $arg2, $arg3, $arg4, $arg5, $arg6)")
  public static Ptr<sock> tcp_v4_syn_recv_sock(Ptr<sock> sk, Ptr<sk_buff> skb,
      Ptr<request_sock> req, Ptr<dst_entry> dst, Ptr<request_sock> req_unhash,
      Ptr<java.lang. @OriginalName("bool") Boolean> own_req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_v4_timewait_ack(Ptr<sock> sk, Ptr<sk_buff> skb, tcp_tw_status tw_status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_v6_ao_calc_key($arg1, $arg2, (const struct in6_addr *)$arg3, (const struct in6_addr *)$arg4, $arg5, $arg6, $arg7, $arg8)")
  public static int tcp_v6_ao_calc_key(Ptr<tcp_ao_key> mkt, Ptr<java.lang.Character> key,
      Ptr<in6_addr> saddr, Ptr<in6_addr> daddr, @Unsigned @OriginalName("__be16") short sport,
      @Unsigned @OriginalName("__be16") short dport, @Unsigned @OriginalName("__be32") int sisn,
      @Unsigned @OriginalName("__be32") int disn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_v6_ao_calc_key_rsk(Ptr<tcp_ao_key> mkt, Ptr<java.lang.Character> key,
      Ptr<request_sock> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_v6_ao_calc_key_sk($arg1, $arg2, (const struct sock *)$arg3, $arg4, $arg5, $arg6)")
  public static int tcp_v6_ao_calc_key_sk(Ptr<tcp_ao_key> mkt, Ptr<java.lang.Character> key,
      Ptr<sock> sk, @Unsigned @OriginalName("__be32") int sisn,
      @Unsigned @OriginalName("__be32") int disn, boolean send) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_v6_ao_calc_key_skb($arg1, $arg2, (const struct sk_buff *)$arg3, $arg4, $arg5)")
  public static int tcp_v6_ao_calc_key_skb(Ptr<tcp_ao_key> mkt, Ptr<java.lang.Character> key,
      Ptr<sk_buff> skb, @Unsigned @OriginalName("__be32") int sisn,
      @Unsigned @OriginalName("__be32") int disn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_v6_ao_hash_pseudoheader($arg1, (const struct in6_addr *)$arg2, (const struct in6_addr *)$arg3, $arg4)")
  public static int tcp_v6_ao_hash_pseudoheader(Ptr<tcp_sigpool> hp, Ptr<in6_addr> daddr,
      Ptr<in6_addr> saddr, int nbytes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_v6_ao_hash_skb($arg1, $arg2, (const struct sock *)$arg3, (const struct sk_buff *)$arg4, (const u8 *)$arg5, $arg6, $arg7)")
  public static int tcp_v6_ao_hash_skb(String ao_hash, Ptr<tcp_ao_key> key, Ptr<sock> sk,
      Ptr<sk_buff> skb, Ptr<java.lang.Character> tkey, int hash_offset, @Unsigned int sne) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_v6_ao_lookup((const struct sock *)$arg1, $arg2, $arg3, $arg4)")
  public static Ptr<tcp_ao_key> tcp_v6_ao_lookup(Ptr<sock> sk, Ptr<sock> addr_sk, int sndid,
      int rcvid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_v6_ao_lookup_rsk((const struct sock *)$arg1, $arg2, $arg3, $arg4)")
  public static Ptr<tcp_ao_key> tcp_v6_ao_lookup_rsk(Ptr<sock> sk, Ptr<request_sock> req, int sndid,
      int rcvid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_v6_ao_synack_hash($arg1, $arg2, $arg3, (const struct sk_buff *)$arg4, $arg5, $arg6)")
  public static int tcp_v6_ao_synack_hash(String ao_hash, Ptr<tcp_ao_key> ao_key,
      Ptr<request_sock> req, Ptr<sk_buff> skb, int hash_offset, @Unsigned int sne) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_v6_conn_request(Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_v6_connect(Ptr<sock> sk, Ptr<sockaddr> uaddr, int addr_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_v6_do_rcv(Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_v6_early_demux(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_v6_err(Ptr<sk_buff> skb, Ptr<inet6_skb_parm> opt, char type, char code,
      int offset, @Unsigned @OriginalName("__be32") int info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_v6_fill_cb($arg1, (const struct ipv6hdr *)$arg2, (const struct tcphdr *)$arg3)")
  public static void tcp_v6_fill_cb(Ptr<sk_buff> skb, Ptr<ipv6hdr> hdr, Ptr<tcphdr> th) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned short tcp_v6_get_syncookie(Ptr<sock> sk, Ptr<ipv6hdr> iph, Ptr<tcphdr> th,
      Ptr<java.lang. @Unsigned Integer> cookie) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_v6_init_seq((const struct sk_buff *)$arg1)")
  public static @Unsigned int tcp_v6_init_seq(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_v6_init_sock(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_v6_init_ts_off((const struct net *)$arg1, (const struct sk_buff *)$arg2)")
  public static @Unsigned int tcp_v6_init_ts_off(Ptr<net> net, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_v6_md5_hash_hdr($arg1, (const struct tcp_md5sig_key *)$arg2, (const struct in6_addr *)$arg3, $arg4, (const struct tcphdr *)$arg5)")
  public static int tcp_v6_md5_hash_hdr(String md5_hash, Ptr<tcp_md5sig_key> key,
      Ptr<in6_addr> daddr, Ptr<in6_addr> saddr, Ptr<tcphdr> th) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_v6_md5_hash_skb($arg1, (const struct tcp_md5sig_key *)$arg2, (const struct sock *)$arg3, (const struct sk_buff *)$arg4)")
  public static int tcp_v6_md5_hash_skb(String md5_hash, Ptr<tcp_md5sig_key> key, Ptr<sock> sk,
      Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_v6_md5_lookup((const struct sock *)$arg1, (const struct sock *)$arg2)")
  public static Ptr<tcp_md5sig_key> tcp_v6_md5_lookup(Ptr<sock> sk, Ptr<sock> addr_sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_v6_mtu_reduced(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_v6_parse_ao(Ptr<sock> sk, int cmd, sockptr_t optval, int optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_v6_parse_md5_keys(Ptr<sock> sk, int optname, sockptr_t optval, int optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_v6_pre_connect(Ptr<sock> sk, Ptr<sockaddr> uaddr, int addr_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_v6_rcv(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_v6_reqsk_destructor(Ptr<request_sock> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_v6_reqsk_send_ack((const struct sock *)$arg1, $arg2, $arg3)")
  public static void tcp_v6_reqsk_send_ack(Ptr<sock> sk, Ptr<sk_buff> skb, Ptr<request_sock> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_v6_restore_cb(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_v6_route_req((const struct sock *)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static Ptr<dst_entry> tcp_v6_route_req(Ptr<sock> sk, Ptr<sk_buff> skb, Ptr<flowi> fl,
      Ptr<request_sock> req, @Unsigned int tw_isn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_v6_send_check(Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_v6_send_reset((const struct sock *)$arg1, $arg2, $arg3)")
  public static void tcp_v6_send_reset(Ptr<sock> sk, Ptr<sk_buff> skb, sk_rst_reason reason) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_v6_send_response((const struct sock *)$arg1, $arg2, $arg3, $arg4, $arg5, $arg6, $arg7, $arg8, $arg9, $arg10, $arg11, $arg12, $arg13, $arg14)")
  public static void tcp_v6_send_response(Ptr<sock> sk, Ptr<sk_buff> skb, @Unsigned int seq,
      @Unsigned int ack, @Unsigned int win, @Unsigned int tsval, @Unsigned int tsecr, int oif,
      int rst, char tclass, @Unsigned @OriginalName("__be32") int label, @Unsigned int priority,
      @Unsigned int txhash, Ptr<tcp_key> key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_v6_send_synack((const struct sock *)$arg1, $arg2, $arg3, $arg4, $arg5, $arg6, $arg7)")
  public static int tcp_v6_send_synack(Ptr<sock> sk, Ptr<dst_entry> dst, Ptr<flowi> fl,
      Ptr<request_sock> req, Ptr<tcp_fastopen_cookie> foc, tcp_synack_type synack_type,
      Ptr<sk_buff> syn_skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_v6_syn_recv_sock((const struct sock *)$arg1, $arg2, $arg3, $arg4, $arg5, $arg6)")
  public static Ptr<sock> tcp_v6_syn_recv_sock(Ptr<sock> sk, Ptr<sk_buff> skb,
      Ptr<request_sock> req, Ptr<dst_entry> dst, Ptr<request_sock> req_unhash,
      Ptr<java.lang. @OriginalName("bool") Boolean> own_req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_v6_timewait_ack(Ptr<sock> sk, Ptr<sk_buff> skb, tcp_tw_status tw_status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_validate_congestion_control(Ptr<tcp_congestion_ops> ca) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("tcp_validate_incoming($arg1, $arg2, (const struct tcphdr *)$arg3, $arg4)")
  public static boolean tcp_validate_incoming(Ptr<sock> sk, Ptr<sk_buff> skb, Ptr<tcphdr> th,
      int syn_inerr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_wfree(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_wmem_schedule(Ptr<sock> sk, int copy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_write_queue_purge(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_write_timeout(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_write_timer(Ptr<timer_list> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_write_timer_handler(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_write_wakeup(Ptr<sock> sk, int mib) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean tcp_write_xmit(Ptr<sock> sk, @Unsigned int mss_now, int nonagle,
      int push_one, @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_xa_pool_commit_locked(Ptr<sock> sk, Ptr<tcp_xa_pool> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_xmit_probe_skb(Ptr<sock> sk, int urgent, int mib) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_xmit_recovery(Ptr<sock> sk, int rexmit) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void tcp_xmit_retransmit_queue(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int tcp_zerocopy_vm_insert_batch(Ptr<vm_area_struct> vma, Ptr<Ptr<page>> pages,
      @Unsigned int pages_to_map, Ptr<java.lang. @Unsigned Long> address,
      Ptr<java.lang. @Unsigned Integer> length, Ptr<java.lang. @Unsigned Integer> seq,
      Ptr<tcp_zerocopy_receive> zc, @Unsigned int total_bytes_to_map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_mib"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_mib extends Struct {
    public @Unsigned long @Size(16) [] mibs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_congestion_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_congestion_ops extends Struct {
    public Ptr<?> ssthresh;

    public Ptr<?> cong_avoid;

    public Ptr<?> set_state;

    public Ptr<?> cwnd_event;

    public Ptr<?> in_ack_event;

    public Ptr<?> pkts_acked;

    public Ptr<?> min_tso_segs;

    public Ptr<?> cong_control;

    public Ptr<?> undo_cwnd;

    public Ptr<?> sndbuf_expand;

    public Ptr<?> get_info;

    public char @Size(16) [] name;

    public Ptr<module> owner;

    public list_head list;

    public @Unsigned int key;

    public @Unsigned int flags;

    public Ptr<?> init;

    public Ptr<?> release;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum tcp_conntrack"
  )
  public enum tcp_conntrack implements Enum<tcp_conntrack>, TypedEnum<tcp_conntrack, java.lang. @Unsigned Integer> {
    /**
     * {@code TCP_CONNTRACK_NONE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "TCP_CONNTRACK_NONE"
    )
    TCP_CONNTRACK_NONE,

    /**
     * {@code TCP_CONNTRACK_SYN_SENT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "TCP_CONNTRACK_SYN_SENT"
    )
    TCP_CONNTRACK_SYN_SENT,

    /**
     * {@code TCP_CONNTRACK_SYN_RECV = 2}
     */
    @EnumMember(
        value = 2L,
        name = "TCP_CONNTRACK_SYN_RECV"
    )
    TCP_CONNTRACK_SYN_RECV,

    /**
     * {@code TCP_CONNTRACK_ESTABLISHED = 3}
     */
    @EnumMember(
        value = 3L,
        name = "TCP_CONNTRACK_ESTABLISHED"
    )
    TCP_CONNTRACK_ESTABLISHED,

    /**
     * {@code TCP_CONNTRACK_FIN_WAIT = 4}
     */
    @EnumMember(
        value = 4L,
        name = "TCP_CONNTRACK_FIN_WAIT"
    )
    TCP_CONNTRACK_FIN_WAIT,

    /**
     * {@code TCP_CONNTRACK_CLOSE_WAIT = 5}
     */
    @EnumMember(
        value = 5L,
        name = "TCP_CONNTRACK_CLOSE_WAIT"
    )
    TCP_CONNTRACK_CLOSE_WAIT,

    /**
     * {@code TCP_CONNTRACK_LAST_ACK = 6}
     */
    @EnumMember(
        value = 6L,
        name = "TCP_CONNTRACK_LAST_ACK"
    )
    TCP_CONNTRACK_LAST_ACK,

    /**
     * {@code TCP_CONNTRACK_TIME_WAIT = 7}
     */
    @EnumMember(
        value = 7L,
        name = "TCP_CONNTRACK_TIME_WAIT"
    )
    TCP_CONNTRACK_TIME_WAIT,

    /**
     * {@code TCP_CONNTRACK_CLOSE = 8}
     */
    @EnumMember(
        value = 8L,
        name = "TCP_CONNTRACK_CLOSE"
    )
    TCP_CONNTRACK_CLOSE,

    /**
     * {@code TCP_CONNTRACK_LISTEN = 9}
     */
    @EnumMember(
        value = 9L,
        name = "TCP_CONNTRACK_LISTEN"
    )
    TCP_CONNTRACK_LISTEN,

    /**
     * {@code TCP_CONNTRACK_MAX = 10}
     */
    @EnumMember(
        value = 10L,
        name = "TCP_CONNTRACK_MAX"
    )
    TCP_CONNTRACK_MAX,

    /**
     * {@code TCP_CONNTRACK_IGNORE = 11}
     */
    @EnumMember(
        value = 11L,
        name = "TCP_CONNTRACK_IGNORE"
    )
    TCP_CONNTRACK_IGNORE,

    /**
     * {@code TCP_CONNTRACK_RETRANS = 12}
     */
    @EnumMember(
        value = 12L,
        name = "TCP_CONNTRACK_RETRANS"
    )
    TCP_CONNTRACK_RETRANS,

    /**
     * {@code TCP_CONNTRACK_UNACK = 13}
     */
    @EnumMember(
        value = 13L,
        name = "TCP_CONNTRACK_UNACK"
    )
    TCP_CONNTRACK_UNACK,

    /**
     * {@code TCP_CONNTRACK_TIMEOUT_MAX = 14}
     */
    @EnumMember(
        value = 14L,
        name = "TCP_CONNTRACK_TIMEOUT_MAX"
    )
    TCP_CONNTRACK_TIMEOUT_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_fastopen_context"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_fastopen_context extends Struct {
    public siphash_key_t @Size(2) [] key;

    public int num;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum tcp_ca_event"
  )
  public enum tcp_ca_event implements Enum<tcp_ca_event>, TypedEnum<tcp_ca_event, java.lang. @Unsigned Integer> {
    /**
     * {@code CA_EVENT_TX_START = 0}
     */
    @EnumMember(
        value = 0L,
        name = "CA_EVENT_TX_START"
    )
    CA_EVENT_TX_START,

    /**
     * {@code CA_EVENT_CWND_RESTART = 1}
     */
    @EnumMember(
        value = 1L,
        name = "CA_EVENT_CWND_RESTART"
    )
    CA_EVENT_CWND_RESTART,

    /**
     * {@code CA_EVENT_COMPLETE_CWR = 2}
     */
    @EnumMember(
        value = 2L,
        name = "CA_EVENT_COMPLETE_CWR"
    )
    CA_EVENT_COMPLETE_CWR,

    /**
     * {@code CA_EVENT_LOSS = 3}
     */
    @EnumMember(
        value = 3L,
        name = "CA_EVENT_LOSS"
    )
    CA_EVENT_LOSS,

    /**
     * {@code CA_EVENT_ECN_NO_CE = 4}
     */
    @EnumMember(
        value = 4L,
        name = "CA_EVENT_ECN_NO_CE"
    )
    CA_EVENT_ECN_NO_CE,

    /**
     * {@code CA_EVENT_ECN_IS_CE = 5}
     */
    @EnumMember(
        value = 5L,
        name = "CA_EVENT_ECN_IS_CE"
    )
    CA_EVENT_ECN_IS_CE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_ulp_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_ulp_ops extends Struct {
    public list_head list;

    public Ptr<?> init;

    public Ptr<?> update;

    public Ptr<?> release;

    public Ptr<?> get_info;

    public Ptr<?> get_info_size;

    public Ptr<?> clone;

    public char @Size(16) [] name;

    public Ptr<module> owner;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_fastopen_cookie"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_fastopen_cookie extends Struct {
    public @Unsigned @OriginalName("__le64") long @Size(2) [] val;

    public @OriginalName("s8") byte len;

    public boolean exp;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_sack_block"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_sack_block extends Struct {
    public @Unsigned int start_seq;

    public @Unsigned int end_seq;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_options_received"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_options_received extends Struct {
    public int ts_recent_stamp;

    public @Unsigned int ts_recent;

    public @Unsigned int rcv_tsval;

    public @Unsigned int rcv_tsecr;

    public @Unsigned short saw_tstamp;

    public @Unsigned short tstamp_ok;

    public @Unsigned short dsack;

    public @Unsigned short wscale_ok;

    public @Unsigned short sack_ok;

    public @Unsigned short smc_ok;

    public @Unsigned short snd_wscale;

    public @Unsigned short rcv_wscale;

    public char saw_unknown;

    public char unused;

    public char num_sacks;

    public @Unsigned short user_mss;

    public @Unsigned short mss_clamp;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_rack"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_rack extends Struct {
    public @Unsigned long mstamp;

    public @Unsigned int rtt_us;

    public @Unsigned int end_seq;

    public @Unsigned int last_delivered;

    public char reo_wnd_steps;

    public char reo_wnd_persist;

    public char dsack_seen;

    public char advanced;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_sock"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_sock extends Struct {
    public inet_connection_sock inet_conn;

    public char @Size(0) [] __cacheline_group_begin__tcp_sock_read_tx;

    public @Unsigned int max_window;

    public @Unsigned int rcv_ssthresh;

    public @Unsigned int reordering;

    public @Unsigned int notsent_lowat;

    public @Unsigned short gso_segs;

    public Ptr<sk_buff> retransmit_skb_hint;

    public char @Size(0) [] __cacheline_group_end__tcp_sock_read_tx;

    public char @Size(0) [] __cacheline_group_begin__tcp_sock_read_txrx;

    public @Unsigned int tsoffset;

    public @Unsigned int snd_wnd;

    public @Unsigned int mss_cache;

    public @Unsigned int snd_cwnd;

    public @Unsigned int prr_out;

    public @Unsigned int lost_out;

    public @Unsigned int sacked_out;

    public @Unsigned short tcp_header_len;

    public char scaling_ratio;

    public char chrono_type;

    public char repair;

    public char tcp_usec_ts;

    public char is_sack_reneg;

    public char is_cwnd_limited;

    public char @Size(0) [] __cacheline_group_end__tcp_sock_read_txrx;

    public char @Size(0) [] __cacheline_group_begin__tcp_sock_read_rx;

    public @Unsigned int copied_seq;

    public @Unsigned int rcv_tstamp;

    public @Unsigned int snd_wl1;

    public @Unsigned int tlp_high_seq;

    public @Unsigned int rttvar_us;

    public @Unsigned int retrans_out;

    public @Unsigned short advmss;

    public @Unsigned short urg_data;

    public @Unsigned int lost;

    public minmax rtt_min;

    public rb_root out_of_order_queue;

    public Ptr<?> tcp_clean_acked;

    public @Unsigned int snd_ssthresh;

    public char recvmsg_inq;

    public char @Size(0) [] __cacheline_group_end__tcp_sock_read_rx;

    public char @Size(0) [] __cacheline_group_begin__tcp_sock_write_tx;

    public @Unsigned int segs_out;

    public @Unsigned int data_segs_out;

    public @Unsigned long bytes_sent;

    public @Unsigned int snd_sml;

    public @Unsigned int chrono_start;

    public @Unsigned int @Size(3) [] chrono_stat;

    public @Unsigned int write_seq;

    public @Unsigned int pushed_seq;

    public @Unsigned int lsndtime;

    public @Unsigned int mdev_us;

    public @Unsigned int rtt_seq;

    public @Unsigned long tcp_wstamp_ns;

    public list_head tsorted_sent_queue;

    public Ptr<sk_buff> highest_sack;

    public char ecn_flags;

    public char @Size(0) [] __cacheline_group_end__tcp_sock_write_tx;

    public char @Size(0) [] __cacheline_group_begin__tcp_sock_write_txrx;

    public @Unsigned @OriginalName("__be32") int pred_flags;

    public @Unsigned long tcp_clock_cache;

    public @Unsigned long tcp_mstamp;

    public @Unsigned int rcv_nxt;

    public @Unsigned int snd_nxt;

    public @Unsigned int snd_una;

    public @Unsigned int window_clamp;

    public @Unsigned int srtt_us;

    public @Unsigned int packets_out;

    public @Unsigned int snd_up;

    public @Unsigned int delivered;

    public @Unsigned int delivered_ce;

    public @Unsigned int app_limited;

    public @Unsigned int rcv_wnd;

    public tcp_options_received rx_opt;

    public char nonagle;

    public char rate_app_limited;

    public char @Size(0) [] __cacheline_group_end__tcp_sock_write_txrx;

    public char @Size(0) [] __cacheline_group_begin__tcp_sock_write_rx;

    public @Unsigned long bytes_received;

    public @Unsigned int segs_in;

    public @Unsigned int data_segs_in;

    public @Unsigned int rcv_wup;

    public @Unsigned int max_packets_out;

    public @Unsigned int cwnd_usage_seq;

    public @Unsigned int rate_delivered;

    public @Unsigned int rate_interval_us;

    public @Unsigned int rcv_rtt_last_tsecr;

    public @Unsigned long first_tx_mstamp;

    public @Unsigned long delivered_mstamp;

    public @Unsigned long bytes_acked;

    public rcv_rtt_est_of_tcp_sock rcv_rtt_est;

    public rcvq_space_of_tcp_sock rcvq_space;

    public char @Size(0) [] __cacheline_group_end__tcp_sock_write_rx;

    public @Unsigned int dsack_dups;

    public @Unsigned int compressed_ack_rcv_nxt;

    public list_head tsq_node;

    public tcp_rack rack;

    public char compressed_ack;

    public char dup_ack_counter;

    public char tlp_retrans;

    public char unused;

    public char thin_lto;

    public char fastopen_connect;

    public char fastopen_no_cookie;

    public char fastopen_client_fail;

    public char frto;

    public char repair_queue;

    public char save_syn;

    public char syn_data;

    public char syn_fastopen;

    public char syn_fastopen_exp;

    public char syn_fastopen_ch;

    public char syn_data_acked;

    public char syn_fastopen_child;

    public char keepalive_probes;

    public @Unsigned int tcp_tx_delay;

    public @Unsigned int mdev_max_us;

    public @Unsigned int reord_seen;

    public @Unsigned int snd_cwnd_cnt;

    public @Unsigned int snd_cwnd_clamp;

    public @Unsigned int snd_cwnd_used;

    public @Unsigned int snd_cwnd_stamp;

    public @Unsigned int prior_cwnd;

    public @Unsigned int prr_delivered;

    public @Unsigned int last_oow_ack_time;

    public hrtimer pacing_timer;

    public hrtimer compressed_ack_timer;

    public Ptr<sk_buff> ooo_last_skb;

    public tcp_sack_block @Size(1) [] duplicate_sack;

    public tcp_sack_block @Size(4) [] selective_acks;

    public tcp_sack_block @Size(4) [] recv_sack_cache;

    public @Unsigned int prior_ssthresh;

    public @Unsigned int high_seq;

    public @Unsigned int retrans_stamp;

    public @Unsigned int undo_marker;

    public int undo_retrans;

    public @Unsigned long bytes_retrans;

    public @Unsigned int total_retrans;

    public @Unsigned int rto_stamp;

    public @Unsigned short total_rto;

    public @Unsigned short total_rto_recoveries;

    public @Unsigned int total_rto_time;

    public @Unsigned int urg_seq;

    public @Unsigned int keepalive_time;

    public @Unsigned int keepalive_intvl;

    public int linger2;

    public char bpf_sock_ops_cb_flags;

    public char bpf_chg_cc_inprogress;

    public @Unsigned short timeout_rehash;

    public @Unsigned int rcv_ooopack;

    public mtu_probe_of_tcp_sock mtu_probe;

    public @Unsigned int plb_rehash;

    public @Unsigned int mtu_info;

    public boolean is_mptcp;

    public boolean syn_smc;

    public Ptr<?> smc_hs_congested;

    public Ptr<tcp_sock_af_ops> af_specific;

    public Ptr<tcp_md5sig_info> md5sig_info;

    public Ptr<tcp_ao_info> ao_info;

    public Ptr<tcp_fastopen_request> fastopen_req;

    public Ptr<request_sock> fastopen_rsk;

    public Ptr<saved_syn> saved_syn;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_sock_af_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_sock_af_ops extends Struct {
    public Ptr<?> md5_lookup;

    public Ptr<?> calc_md5_hash;

    public Ptr<?> md5_parse;

    public Ptr<?> ao_parse;

    public Ptr<?> ao_lookup;

    public Ptr<?> ao_calc_key_sk;

    public Ptr<?> calc_ao_hash;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_md5sig_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_md5sig_info extends Struct {
    public hlist_head head;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_ao_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_ao_info extends Struct {
    public hlist_head head;

    public Ptr<tcp_ao_key> current_key;

    public Ptr<tcp_ao_key> rnext_key;

    public tcp_ao_counters counters;

    public @Unsigned int ao_required;

    public @Unsigned int accept_icmps;

    public @Unsigned int __unused;

    public @Unsigned @OriginalName("__be32") int lisn;

    public @Unsigned @OriginalName("__be32") int risn;

    public @Unsigned int snd_sne;

    public @Unsigned int rcv_sne;

    public @OriginalName("refcount_t") refcount_struct refcnt;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_fastopen_request"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_fastopen_request extends Struct {
    public tcp_fastopen_cookie cookie;

    public Ptr<msghdr> data;

    public @Unsigned long size;

    public int copied;

    public Ptr<ubuf_info> uarg;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_md5sig_key"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_md5sig_key extends Struct {
    public hlist_node node;

    public char keylen;

    public char family;

    public char prefixlen;

    public char flags;

    public tcp_ao_addr addr;

    public int l3index;

    public char @Size(80) [] key;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union tcp_ao_addr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_ao_addr extends Union {
    public in_addr a4;

    public in6_addr a6;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_ao_counters"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_ao_counters extends Struct {
    public atomic64_t pkt_good;

    public atomic64_t pkt_bad;

    public atomic64_t key_not_found;

    public atomic64_t ao_required;

    public atomic64_t dropped_icmp;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_ao_key"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_ao_key extends Struct {
    public hlist_node node;

    public tcp_ao_addr addr;

    public char @Size(80) [] key;

    public @Unsigned int tcp_sigpool_id;

    public @Unsigned int digest_size;

    public int l3index;

    public char prefixlen;

    public char family;

    public char keylen;

    public char keyflags;

    public char sndid;

    public char rcvid;

    public char maclen;

    public callback_head rcu;

    public atomic64_t pkt_good;

    public atomic64_t pkt_bad;

    public char @Size(0) [] traffic_keys;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_request_sock"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_request_sock extends Struct {
    public inet_request_sock req;

    public Ptr<tcp_request_sock_ops> af_specific;

    public @Unsigned long snt_synack;

    public boolean tfo_listener;

    public boolean is_mptcp;

    public boolean req_usec_ts;

    public boolean drop_req;

    public @Unsigned int txhash;

    public @Unsigned int rcv_isn;

    public @Unsigned int snt_isn;

    public @Unsigned int ts_off;

    public @Unsigned int snt_tsval_first;

    public @Unsigned int snt_tsval_last;

    public @Unsigned int last_oow_ack_time;

    public @Unsigned int rcv_nxt;

    public char syn_tos;

    public char ao_keyid;

    public char ao_rcv_next;

    public boolean used_tcp_ao;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_request_sock_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_request_sock_ops extends Struct {
    public @Unsigned short mss_clamp;

    public Ptr<?> req_md5_lookup;

    public Ptr<?> calc_md5_hash;

    public Ptr<?> ao_lookup;

    public Ptr<?> ao_calc_key;

    public Ptr<?> ao_synack_hash;

    public Ptr<?> cookie_init_seq;

    public Ptr<?> route_req;

    public Ptr<?> init_seq;

    public Ptr<?> init_ts_off;

    public Ptr<?> send_synack;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_skb_cb"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_skb_cb extends Struct {
    public @Unsigned int seq;

    public @Unsigned int end_seq;

    @InlineUnion(57065)
    public anon_member_of_anon_member_of_tcp_skb_cb anon2$0;

    public @Unsigned short tcp_flags;

    public char sacked;

    public char ip_dsfield;

    public char txstamp_ack;

    public char eor;

    public char has_rxtstamp;

    public char unused;

    public @Unsigned int ack_seq;

    @InlineUnion(57067)
    public tx_of_anon_member_of_tcp_skb_cb tx;

    @InlineUnion(57067)
    public anon_member_of_ipfrag_skb_cb_and_header_of_anon_member_of_tcp_skb_cb_and_header_of_sock_exterr_skb header;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union tcp_word_hdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_word_hdr extends Union {
    public tcphdr hdr;

    public @Unsigned @OriginalName("__be32") int @Size(5) [] words;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_timewait_sock"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_timewait_sock extends Struct {
    public inet_timewait_sock tw_sk;

    public @Unsigned int tw_rcv_wnd;

    public @Unsigned int tw_ts_offset;

    public @Unsigned int tw_ts_recent;

    public @Unsigned int tw_last_oow_ack_time;

    public int tw_ts_recent_stamp;

    public @Unsigned int tw_tx_delay;

    public Ptr<tcp_md5sig_key> tw_md5_key;

    public Ptr<tcp_ao_info> ao_info;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum tcp_synack_type"
  )
  public enum tcp_synack_type implements Enum<tcp_synack_type>, TypedEnum<tcp_synack_type, java.lang. @Unsigned Integer> {
    /**
     * {@code TCP_SYNACK_NORMAL = 0}
     */
    @EnumMember(
        value = 0L,
        name = "TCP_SYNACK_NORMAL"
    )
    TCP_SYNACK_NORMAL,

    /**
     * {@code TCP_SYNACK_FASTOPEN = 1}
     */
    @EnumMember(
        value = 1L,
        name = "TCP_SYNACK_FASTOPEN"
    )
    TCP_SYNACK_FASTOPEN,

    /**
     * {@code TCP_SYNACK_COOKIE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "TCP_SYNACK_COOKIE"
    )
    TCP_SYNACK_COOKIE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum tcp_ca_state"
  )
  public enum tcp_ca_state implements Enum<tcp_ca_state>, TypedEnum<tcp_ca_state, java.lang. @Unsigned Integer> {
    /**
     * {@code TCP_CA_Open = 0}
     */
    @EnumMember(
        value = 0L,
        name = "TCP_CA_Open"
    )
    TCP_CA_Open,

    /**
     * {@code TCP_CA_Disorder = 1}
     */
    @EnumMember(
        value = 1L,
        name = "TCP_CA_Disorder"
    )
    TCP_CA_Disorder,

    /**
     * {@code TCP_CA_CWR = 2}
     */
    @EnumMember(
        value = 2L,
        name = "TCP_CA_CWR"
    )
    TCP_CA_CWR,

    /**
     * {@code TCP_CA_Recovery = 3}
     */
    @EnumMember(
        value = 3L,
        name = "TCP_CA_Recovery"
    )
    TCP_CA_Recovery,

    /**
     * {@code TCP_CA_Loss = 4}
     */
    @EnumMember(
        value = 4L,
        name = "TCP_CA_Loss"
    )
    TCP_CA_Loss
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_dctcp_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_dctcp_info extends Struct {
    public @Unsigned short dctcp_enabled;

    public @Unsigned short dctcp_ce_state;

    public @Unsigned int dctcp_alpha;

    public @Unsigned int dctcp_ab_ecn;

    public @Unsigned int dctcp_ab_tot;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_bbr_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_bbr_info extends Struct {
    public @Unsigned int bbr_bw_lo;

    public @Unsigned int bbr_bw_hi;

    public @Unsigned int bbr_min_rtt;

    public @Unsigned int bbr_pacing_gain;

    public @Unsigned int bbr_cwnd_gain;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union tcp_cc_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_cc_info extends Union {
    public tcpvegas_info vegas;

    public tcp_dctcp_info dctcp;

    public tcp_bbr_info bbr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_repair_opt"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_repair_opt extends Struct {
    public @Unsigned int opt_code;

    public @Unsigned int opt_val;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_repair_window"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_repair_window extends Struct {
    public @Unsigned int snd_wl1;

    public @Unsigned int snd_wnd;

    public @Unsigned int max_window;

    public @Unsigned int rcv_wnd;

    public @Unsigned int rcv_wup;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_info extends Struct {
    public char tcpi_state;

    public char tcpi_ca_state;

    public char tcpi_retransmits;

    public char tcpi_probes;

    public char tcpi_backoff;

    public char tcpi_options;

    public char tcpi_snd_wscale;

    public char tcpi_rcv_wscale;

    public char tcpi_delivery_rate_app_limited;

    public char tcpi_fastopen_client_fail;

    public @Unsigned int tcpi_rto;

    public @Unsigned int tcpi_ato;

    public @Unsigned int tcpi_snd_mss;

    public @Unsigned int tcpi_rcv_mss;

    public @Unsigned int tcpi_unacked;

    public @Unsigned int tcpi_sacked;

    public @Unsigned int tcpi_lost;

    public @Unsigned int tcpi_retrans;

    public @Unsigned int tcpi_fackets;

    public @Unsigned int tcpi_last_data_sent;

    public @Unsigned int tcpi_last_ack_sent;

    public @Unsigned int tcpi_last_data_recv;

    public @Unsigned int tcpi_last_ack_recv;

    public @Unsigned int tcpi_pmtu;

    public @Unsigned int tcpi_rcv_ssthresh;

    public @Unsigned int tcpi_rtt;

    public @Unsigned int tcpi_rttvar;

    public @Unsigned int tcpi_snd_ssthresh;

    public @Unsigned int tcpi_snd_cwnd;

    public @Unsigned int tcpi_advmss;

    public @Unsigned int tcpi_reordering;

    public @Unsigned int tcpi_rcv_rtt;

    public @Unsigned int tcpi_rcv_space;

    public @Unsigned int tcpi_total_retrans;

    public @Unsigned long tcpi_pacing_rate;

    public @Unsigned long tcpi_max_pacing_rate;

    public @Unsigned long tcpi_bytes_acked;

    public @Unsigned long tcpi_bytes_received;

    public @Unsigned int tcpi_segs_out;

    public @Unsigned int tcpi_segs_in;

    public @Unsigned int tcpi_notsent_bytes;

    public @Unsigned int tcpi_min_rtt;

    public @Unsigned int tcpi_data_segs_in;

    public @Unsigned int tcpi_data_segs_out;

    public @Unsigned long tcpi_delivery_rate;

    public @Unsigned long tcpi_busy_time;

    public @Unsigned long tcpi_rwnd_limited;

    public @Unsigned long tcpi_sndbuf_limited;

    public @Unsigned int tcpi_delivered;

    public @Unsigned int tcpi_delivered_ce;

    public @Unsigned long tcpi_bytes_sent;

    public @Unsigned long tcpi_bytes_retrans;

    public @Unsigned int tcpi_dsack_dups;

    public @Unsigned int tcpi_reord_seen;

    public @Unsigned int tcpi_rcv_ooopack;

    public @Unsigned int tcpi_snd_wnd;

    public @Unsigned int tcpi_rcv_wnd;

    public @Unsigned int tcpi_rehash;

    public @Unsigned short tcpi_total_rto;

    public @Unsigned short tcpi_total_rto_recoveries;

    public @Unsigned int tcpi_total_rto_time;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_zerocopy_receive"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_zerocopy_receive extends Struct {
    public @Unsigned long address;

    public @Unsigned int length;

    public @Unsigned int recv_skip_hint;

    public @Unsigned int inq;

    public int err;

    public @Unsigned long copybuf_address;

    public int copybuf_len;

    public @Unsigned int flags;

    public @Unsigned long msg_control;

    public @Unsigned long msg_controllen;

    public @Unsigned int msg_flags;

    public @Unsigned int reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_ao_hdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_ao_hdr extends Struct {
    public char kind;

    public char length;

    public char keyid;

    public char rnext_keyid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum tcp_skb_cb_sacked_flags"
  )
  public enum tcp_skb_cb_sacked_flags implements Enum<tcp_skb_cb_sacked_flags>, TypedEnum<tcp_skb_cb_sacked_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code TCPCB_SACKED_ACKED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "TCPCB_SACKED_ACKED"
    )
    TCPCB_SACKED_ACKED,

    /**
     * {@code TCPCB_SACKED_RETRANS = 2}
     */
    @EnumMember(
        value = 2L,
        name = "TCPCB_SACKED_RETRANS"
    )
    TCPCB_SACKED_RETRANS,

    /**
     * {@code TCPCB_LOST = 4}
     */
    @EnumMember(
        value = 4L,
        name = "TCPCB_LOST"
    )
    TCPCB_LOST,

    /**
     * {@code TCPCB_TAGBITS = 7}
     */
    @EnumMember(
        value = 7L,
        name = "TCPCB_TAGBITS"
    )
    TCPCB_TAGBITS,

    /**
     * {@code TCPCB_REPAIRED = 16}
     */
    @EnumMember(
        value = 16L,
        name = "TCPCB_REPAIRED"
    )
    TCPCB_REPAIRED,

    /**
     * {@code TCPCB_EVER_RETRANS = 128}
     */
    @EnumMember(
        value = 128L,
        name = "TCPCB_EVER_RETRANS"
    )
    TCPCB_EVER_RETRANS,

    /**
     * {@code TCPCB_RETRANS = 146}
     */
    @EnumMember(
        value = 146L,
        name = "TCPCB_RETRANS"
    )
    TCPCB_RETRANS
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_sigpool"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_sigpool extends Struct {
    public Ptr<?> scratch;

    public Ptr<ahash_request> req;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum tcp_chrono"
  )
  public enum tcp_chrono implements Enum<tcp_chrono>, TypedEnum<tcp_chrono, java.lang. @Unsigned Integer> {
    /**
     * {@code TCP_CHRONO_UNSPEC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "TCP_CHRONO_UNSPEC"
    )
    TCP_CHRONO_UNSPEC,

    /**
     * {@code TCP_CHRONO_BUSY = 1}
     */
    @EnumMember(
        value = 1L,
        name = "TCP_CHRONO_BUSY"
    )
    TCP_CHRONO_BUSY,

    /**
     * {@code TCP_CHRONO_RWND_LIMITED = 2}
     */
    @EnumMember(
        value = 2L,
        name = "TCP_CHRONO_RWND_LIMITED"
    )
    TCP_CHRONO_RWND_LIMITED,

    /**
     * {@code TCP_CHRONO_SNDBUF_LIMITED = 3}
     */
    @EnumMember(
        value = 3L,
        name = "TCP_CHRONO_SNDBUF_LIMITED"
    )
    TCP_CHRONO_SNDBUF_LIMITED,

    /**
     * {@code __TCP_CHRONO_MAX = 4}
     */
    @EnumMember(
        value = 4L,
        name = "__TCP_CHRONO_MAX"
    )
    __TCP_CHRONO_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_splice_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_splice_state extends Struct {
    public Ptr<pipe_inode_info> pipe;

    public @Unsigned long len;

    public @Unsigned int flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_xa_pool"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_xa_pool extends Struct {
    public char max;

    public char idx;

    public @Unsigned int @Size(17) [] tokens;

    public @Unsigned @OriginalName("netmem_ref") long @Size(17) [] netmems;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum tcp_fastopen_client_fail"
  )
  public enum tcp_fastopen_client_fail implements Enum<tcp_fastopen_client_fail>, TypedEnum<tcp_fastopen_client_fail, java.lang. @Unsigned Integer> {
    /**
     * {@code TFO_STATUS_UNSPEC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "TFO_STATUS_UNSPEC"
    )
    TFO_STATUS_UNSPEC,

    /**
     * {@code TFO_COOKIE_UNAVAILABLE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "TFO_COOKIE_UNAVAILABLE"
    )
    TFO_COOKIE_UNAVAILABLE,

    /**
     * {@code TFO_DATA_NOT_ACKED = 2}
     */
    @EnumMember(
        value = 2L,
        name = "TFO_DATA_NOT_ACKED"
    )
    TFO_DATA_NOT_ACKED,

    /**
     * {@code TFO_SYN_RETRANSMITTED = 3}
     */
    @EnumMember(
        value = 3L,
        name = "TFO_SYN_RETRANSMITTED"
    )
    TFO_SYN_RETRANSMITTED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_sack_block_wire"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_sack_block_wire extends Struct {
    public @Unsigned @OriginalName("__be32") int start_seq;

    public @Unsigned @OriginalName("__be32") int end_seq;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum tcp_queue"
  )
  public enum tcp_queue implements Enum<tcp_queue>, TypedEnum<tcp_queue, java.lang. @Unsigned Integer> {
    /**
     * {@code TCP_FRAG_IN_WRITE_QUEUE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "TCP_FRAG_IN_WRITE_QUEUE"
    )
    TCP_FRAG_IN_WRITE_QUEUE,

    /**
     * {@code TCP_FRAG_IN_RTX_QUEUE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "TCP_FRAG_IN_RTX_QUEUE"
    )
    TCP_FRAG_IN_RTX_QUEUE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum tcp_ca_ack_event_flags"
  )
  public enum tcp_ca_ack_event_flags implements Enum<tcp_ca_ack_event_flags>, TypedEnum<tcp_ca_ack_event_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code CA_ACK_SLOWPATH = 1}
     */
    @EnumMember(
        value = 1L,
        name = "CA_ACK_SLOWPATH"
    )
    CA_ACK_SLOWPATH,

    /**
     * {@code CA_ACK_WIN_UPDATE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "CA_ACK_WIN_UPDATE"
    )
    CA_ACK_WIN_UPDATE,

    /**
     * {@code CA_ACK_ECE = 4}
     */
    @EnumMember(
        value = 4L,
        name = "CA_ACK_ECE"
    )
    CA_ACK_ECE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_sacktag_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_sacktag_state extends Struct {
    public @Unsigned long first_sackt;

    public @Unsigned long last_sackt;

    public @Unsigned int reord;

    public @Unsigned int sack_delivered;

    public int flag;

    public @Unsigned int mss_now;

    public Ptr<rate_sample> rate;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_key"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_key extends Struct {
    @InlineUnion(61879)
    public anon_member_of_anon_member_of_tcp_key anon0$0;

    @InlineUnion(61879)
    public Ptr<tcp_md5sig_key> md5_key;

    public type_of_tcp_key type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_out_options"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_out_options extends Struct {
    public @Unsigned short options;

    public @Unsigned short mss;

    public char ws;

    public char num_sack_blocks;

    public char hash_size;

    public char bpf_opt_len;

    public Ptr<java.lang.Character> hash_location;

    public @Unsigned int tsval;

    public @Unsigned int tsecr;

    public Ptr<tcp_fastopen_cookie> fastopen_cookie;

    public mptcp_out_options mptcp;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_md5sig"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_md5sig extends Struct {
    public __kernel_sockaddr_storage tcpm_addr;

    public char tcpm_flags;

    public char tcpm_prefixlen;

    public @Unsigned short tcpm_keylen;

    public int tcpm_ifindex;

    public char @Size(80) [] tcpm_key;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum tcp_tw_status"
  )
  public enum tcp_tw_status implements Enum<tcp_tw_status>, TypedEnum<tcp_tw_status, java.lang. @Unsigned Integer> {
    /**
     * {@code TCP_TW_SUCCESS = 0}
     */
    @EnumMember(
        value = 0L,
        name = "TCP_TW_SUCCESS"
    )
    TCP_TW_SUCCESS,

    /**
     * {@code TCP_TW_RST = 1}
     */
    @EnumMember(
        value = 1L,
        name = "TCP_TW_RST"
    )
    TCP_TW_RST,

    /**
     * {@code TCP_TW_ACK = 2}
     */
    @EnumMember(
        value = 2L,
        name = "TCP_TW_ACK"
    )
    TCP_TW_ACK,

    /**
     * {@code TCP_TW_SYN = 3}
     */
    @EnumMember(
        value = 3L,
        name = "TCP_TW_SYN"
    )
    TCP_TW_SYN,

    /**
     * {@code TCP_TW_ACK_OOW = 4}
     */
    @EnumMember(
        value = 4L,
        name = "TCP_TW_ACK_OOW"
    )
    TCP_TW_ACK_OOW
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum tcp_seq_states"
  )
  public enum tcp_seq_states implements Enum<tcp_seq_states>, TypedEnum<tcp_seq_states, java.lang. @Unsigned Integer> {
    /**
     * {@code TCP_SEQ_STATE_LISTENING = 0}
     */
    @EnumMember(
        value = 0L,
        name = "TCP_SEQ_STATE_LISTENING"
    )
    TCP_SEQ_STATE_LISTENING,

    /**
     * {@code TCP_SEQ_STATE_ESTABLISHED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "TCP_SEQ_STATE_ESTABLISHED"
    )
    TCP_SEQ_STATE_ESTABLISHED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_seq_afinfo"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_seq_afinfo extends Struct {
    public @Unsigned @OriginalName("sa_family_t") short family;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_iter_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_iter_state extends Struct {
    public seq_net_private p;

    public tcp_seq_states state;

    public Ptr<sock> syn_wait_sk;

    public int bucket;

    public int offset;

    public int sbucket;

    public int num;

    public @OriginalName("loff_t") long last_pos;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum tcp_metric_index"
  )
  public enum tcp_metric_index implements Enum<tcp_metric_index>, TypedEnum<tcp_metric_index, java.lang. @Unsigned Integer> {
    /**
     * {@code TCP_METRIC_RTT = 0}
     */
    @EnumMember(
        value = 0L,
        name = "TCP_METRIC_RTT"
    )
    TCP_METRIC_RTT,

    /**
     * {@code TCP_METRIC_RTTVAR = 1}
     */
    @EnumMember(
        value = 1L,
        name = "TCP_METRIC_RTTVAR"
    )
    TCP_METRIC_RTTVAR,

    /**
     * {@code TCP_METRIC_SSTHRESH = 2}
     */
    @EnumMember(
        value = 2L,
        name = "TCP_METRIC_SSTHRESH"
    )
    TCP_METRIC_SSTHRESH,

    /**
     * {@code TCP_METRIC_CWND = 3}
     */
    @EnumMember(
        value = 3L,
        name = "TCP_METRIC_CWND"
    )
    TCP_METRIC_CWND,

    /**
     * {@code TCP_METRIC_REORDERING = 4}
     */
    @EnumMember(
        value = 4L,
        name = "TCP_METRIC_REORDERING"
    )
    TCP_METRIC_REORDERING,

    /**
     * {@code TCP_METRIC_RTT_US = 5}
     */
    @EnumMember(
        value = 5L,
        name = "TCP_METRIC_RTT_US"
    )
    TCP_METRIC_RTT_US,

    /**
     * {@code TCP_METRIC_RTTVAR_US = 6}
     */
    @EnumMember(
        value = 6L,
        name = "TCP_METRIC_RTTVAR_US"
    )
    TCP_METRIC_RTTVAR_US,

    /**
     * {@code __TCP_METRIC_MAX = 7}
     */
    @EnumMember(
        value = 7L,
        name = "__TCP_METRIC_MAX"
    )
    __TCP_METRIC_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_fastopen_metrics"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_fastopen_metrics extends Struct {
    public @Unsigned short mss;

    public @Unsigned short syn_loss;

    public @Unsigned short try_exp;

    public @Unsigned long last_syn_loss;

    public tcp_fastopen_cookie cookie;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_metrics_block"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_metrics_block extends Struct {
    public Ptr<tcp_metrics_block> tcpm_next;

    public Ptr<net> tcpm_net;

    public inetpeer_addr tcpm_saddr;

    public inetpeer_addr tcpm_daddr;

    public @Unsigned long tcpm_stamp;

    public @Unsigned int tcpm_lock;

    public @Unsigned int @Size(5) [] tcpm_vals;

    public tcp_fastopen_metrics tcpm_fastopen;

    public callback_head callback_head;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_plb_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_plb_state extends Struct {
    public char consec_cong_rounds;

    public char unused;

    public @Unsigned int pause_until;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_ao_add"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_ao_add extends Struct {
    public __kernel_sockaddr_storage addr;

    public char @Size(64) [] alg_name;

    public int ifindex;

    public @Unsigned int set_current;

    public @Unsigned int set_rnext;

    public @Unsigned int reserved;

    public @Unsigned short reserved2;

    public char prefix;

    public char sndid;

    public char rcvid;

    public char maclen;

    public char keyflags;

    public char keylen;

    public char @Size(80) [] key;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_ao_del"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_ao_del extends Struct {
    public __kernel_sockaddr_storage addr;

    public int ifindex;

    public @Unsigned int set_current;

    public @Unsigned int set_rnext;

    public @Unsigned int del_async;

    public @Unsigned int reserved;

    public @Unsigned short reserved2;

    public char prefix;

    public char sndid;

    public char rcvid;

    public char current_key;

    public char rnext;

    public char keyflags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_ao_info_opt"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_ao_info_opt extends Struct {
    public @Unsigned int set_current;

    public @Unsigned int set_rnext;

    public @Unsigned int ao_required;

    public @Unsigned int set_counters;

    public @Unsigned int accept_icmps;

    public @Unsigned int reserved;

    public @Unsigned short reserved2;

    public char current_key;

    public char rnext;

    public @Unsigned long pkt_good;

    public @Unsigned long pkt_bad;

    public @Unsigned long pkt_key_not_found;

    public @Unsigned long pkt_ao_required;

    public @Unsigned long pkt_dropped_icmp;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_ao_getsockopt"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_ao_getsockopt extends Struct {
    public __kernel_sockaddr_storage addr;

    public char @Size(64) [] alg_name;

    public char @Size(80) [] key;

    public @Unsigned int nkeys;

    public @Unsigned short is_current;

    public @Unsigned short is_rnext;

    public @Unsigned short get_all;

    public @Unsigned short reserved;

    public char sndid;

    public char rcvid;

    public char prefix;

    public char maclen;

    public char keyflags;

    public char keylen;

    public int ifindex;

    public @Unsigned long pkt_good;

    public @Unsigned long pkt_bad;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct tcp_ao_repair"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class tcp_ao_repair extends Struct {
    public @Unsigned @OriginalName("__be32") int snt_isn;

    public @Unsigned @OriginalName("__be32") int rcv_isn;

    public @Unsigned int snd_sne;

    public @Unsigned int rcv_sne;
  }
}
